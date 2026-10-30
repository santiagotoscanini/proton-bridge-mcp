"""MIME, on the standard library's email package (policy.default).

The stdlib parses messages, decodes headers (RFC 2047), parameters and
filenames (RFC 2231) and transfer encodings. This module adds what the
tools need on top, and repairs exactly three things real mail defeats the
stdlib on:

- a character split across two encoded words (the stdlib decodes each
  word alone and leaves surrogate escapes): the words' bytes are joined
  before decoding;
- an unknown or bogus charset label (the stdlib raises LookupError);
- windows-1252 text labelled ISO-8859-1 or US-ASCII (the stdlib yields C1
  control characters): those labels decode as windows-1252, as WHATWG and
  every mail client do.

Parts are numbered as IMAP numbers them (RFC 3501), whether the tree comes
from a whole local message or from a server BODYSTRUCTURE (when only
chosen parts will be fetched), so BODY.PEEK[<section>] addresses either."""

from __future__ import annotations

import binascii
import codecs
import email
import email.policy
import email.utils
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from typing import Any

POLICY = email.policy.default

# ── charsets and transfer encodings ──────────────────────────────────────

_CHARSET_ALIASES = {
    "us-ascii": "cp1252",
    "ascii": "cp1252",
    "iso-8859-1": "cp1252",
    "iso8859-1": "cp1252",
    "iso_8859-1": "cp1252",
    "latin1": "cp1252",
    "latin-1": "cp1252",
    "l1": "cp1252",
    "utf8": "utf-8",
    "ks_c_5601-1987": "cp949",
    "gb2312": "gb18030",
    "gbk": "gb18030",
    "x-gbk": "gb18030",
    "x-sjis": "shift_jis",
    "unknown-8bit": "",
    "x-unknown": "",
    "default": "",
}


def _codec(charset: str | None) -> str | None:
    if not charset:
        return None
    label = charset.strip().strip("\"'").lower().split("*", 1)[0]
    label = _CHARSET_ALIASES.get(label, label)
    if not label:
        return None
    try:
        return codecs.lookup(label).name
    except LookupError:
        return None


def decode_text(data: bytes, charset: str | None = None) -> str:
    """Bytes to text: BOM first, then the declared charset, then UTF-8,
    then windows-1252. Never raises."""
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", "replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", "replace")
    codec = _codec(charset)
    if codec and codec not in ("utf-8", "cp1252"):
        try:
            return data.decode(codec)
        except (UnicodeDecodeError, LookupError):
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A partial fetch can cut the last character in half: drop it
        # rather than read the whole text as windows-1252.
        if exc.reason == "unexpected end of data" and exc.start >= len(data) - 3:
            try:
                return data[: exc.start].decode("utf-8")
            except UnicodeDecodeError:
                pass
        if codec and codec != "cp1252":
            return data.decode(codec, "replace")
        return data.decode("cp1252", "replace")


def decode_transfer(data: bytes, cte: str | None) -> bytes:
    """For a part fetched on its own by section (there is no EmailMessage
    around it to ask)."""
    enc = (cte or "").strip().lower()
    if enc == "base64":
        clean = re.sub(rb"[^A-Za-z0-9+/]", b"", data)
        clean = clean[: len(clean) - (len(clean) % 4 == 1)]
        try:
            return binascii.a2b_base64(clean + b"=" * (-len(clean) % 4))
        except binascii.Error:
            return b""
    if enc == "quoted-printable":
        return binascii.a2b_qp(data)
    return data


def decode_partial_transfer(data: bytes, cte: str | None) -> bytes:
    """The first N bytes of an encoded part, cut at a clean boundary."""
    enc = (cte or "").strip().lower()
    if enc == "quoted-printable":
        cut = data.rfind(b"=", max(0, len(data) - 2))
        if cut >= 0:
            data = data[:cut]
    elif enc == "base64":
        clean = re.sub(rb"[^A-Za-z0-9+/]", b"", data)
        data = clean[: len(clean) - len(clean) % 4]
    return decode_transfer(data, cte)


# ── headers ──────────────────────────────────────────────────────────────

_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([QqBb])\?([^?\s]*)\?=")
_FOLD = re.compile(r"\r?\n[ \t]")
_SURROGATE = re.compile(r"[\udc80-\udcff]")


def _word_bytes(encoding: str, payload: str) -> bytes:
    if encoding.upper() == "Q":
        return binascii.a2b_qp(payload.replace("_", " ").encode("ascii", "replace"), header=False)
    clean = re.sub(r"[^A-Za-z0-9+/]", "", payload)
    clean = clean[: len(clean) - (len(clean) % 4 == 1)]
    try:
        return binascii.a2b_base64(clean + "=" * (-len(clean) % 4))
    except binascii.Error:
        return b""


def _joined_words(raw: str) -> str:
    """RFC 2047 with adjacent same-charset words joined as bytes first: the
    repair for a character split across two words."""
    text = _FOLD.sub(" ", raw)
    if _SURROGATE.search(text):
        text = decode_text(text.encode("ascii", "surrogateescape"))
    out: list[str] = []
    pending: bytearray | None = None
    charset: str | None = None
    pos = 0
    for m in _ENCODED_WORD.finditer(text):
        between = text[pos : m.start()]
        if pending is not None and not between.strip() and _codec(m.group(1)) == _codec(charset):
            pending.extend(_word_bytes(m.group(2), m.group(3)))
        else:
            if pending is not None:
                out.append(decode_text(bytes(pending), charset))
            if pending is None or between.strip():
                out.append(between)
            pending, charset = bytearray(_word_bytes(m.group(2), m.group(3))), m.group(1)
        pos = m.end()
    if pending is not None:
        out.append(decode_text(bytes(pending), charset))
    out.append(text[pos:])
    return "".join(out).strip()


def decode_header(raw: Any) -> str:
    """A raw header value (or an ENVELOPE string) as text."""
    if raw is None:
        return ""
    raw = str(raw)
    try:
        text = str(POLICY.header_fetch_parse("Subject", raw))
    except Exception:  # noqa: BLE001 - malformed values fall back to the repair
        text = ""
    if not text or _SURROGATE.search(text) or "�" in text:
        text = _joined_words(raw)
    return text.replace("\r", "").replace("\n", " ").strip()


@dataclass(frozen=True)
class Address:
    name: str
    address: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "address": self.address}

    def formatted(self) -> str:
        return email.utils.formataddr((self.name, self.address)) if self.name else self.address


def normalize_address(addr: str) -> str:
    """Lower-cased, '+tag' stripped: how Bridge compares sender addresses."""
    local, at, domain = addr.strip().lower().partition("@")
    if not at:
        return local
    if "+" in local[1:]:
        local = local[: local.index("+", 1)]
    return f"{local}@{domain}"


class Headers:
    """A message's raw headers in order; decoded by the stdlib on read."""

    def __init__(self, items: list[tuple[str, Any]]) -> None:
        self._items = [(k, str(v)) for k, v in items]

    @classmethod
    def from_bytes(cls, raw: bytes) -> Headers:
        return cls(list(BytesHeaderParser(policy=POLICY).parsebytes(raw).raw_items()))

    def raw_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [v for k, v in self._items if k.lower() == lname]

    def get(self, name: str) -> str | None:
        values = self.raw_all(name)
        return decode_header(values[0]) if values else None

    def get_all(self, name: str) -> list[str]:
        return [decode_header(v) for v in self.raw_all(name)]

    def addresses(self, *names: str) -> list[Address]:
        out: list[Address] = []
        for name in names:
            for raw in self.raw_all(name):
                out.extend(_addresses(name, raw))
        return out

    def names(self) -> list[str]:
        return [k for k, _ in self._items]


def _addresses(name: str, raw: str) -> list[Address]:
    try:
        parsed = [(a.display_name, a.addr_spec) for a in POLICY.header_fetch_parse(name, raw).addresses]
    except Exception:  # noqa: BLE001
        parsed = []
    if not parsed or any(_SURROGATE.search(n) for n, _ in parsed):
        # Split encoded words (or an address list the stdlib gave up on):
        # split the raw list first, then decode each display name.
        parsed = [(_joined_words(n), a) for n, a in email.utils.getaddresses([_FOLD.sub(" ", raw)])]
    return [Address(n.strip(), a.strip()) for n, a in parsed if a and "@" in a]


_MSGID = re.compile(r"<([^<>\s]+)>")
INTERNAL_ID_DOMAIN = "@protonmail.internalid"


def message_ids(value: str | None) -> list[str]:
    """The <ids> in a Message-ID / In-Reply-To / References value, in order."""
    return [m.group(1) for m in _MSGID.finditer(value or "")]


# ── the part tree ────────────────────────────────────────────────────────


@dataclass(eq=False)
class Part:
    maintype: str
    subtype: str
    params: dict[str, str] = field(default_factory=dict)
    disposition: str | None = None
    filename: str | None = None
    content_id: str | None = None
    cte: str = "7bit"
    size: int = 0  # encoded octets, from BODYSTRUCTURE
    children: list[Part] = field(default_factory=list)
    message: Part | None = None  # the encapsulated message of a message/rfc822 part
    section: str = ""
    local: EmailMessage | None = None  # the stdlib part, when the whole message is here

    @property
    def content_type(self) -> str:
        return f"{self.maintype}/{self.subtype}"

    @property
    def is_multipart(self) -> bool:
        return self.maintype == "multipart"

    @property
    def charset(self) -> str | None:
        return self.params.get("charset")

    @property
    def is_attachment(self) -> bool:
        if self.disposition == "attachment":
            return True
        return bool(self.filename) and self.disposition != "inline"

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()
        if self.message is not None:
            yield from self.message.walk()

    def find(self, section: str) -> Part | None:
        for part in self.walk():
            if part.section == section and not part.is_multipart:
                return part
        return None

    def decoded(self) -> bytes:
        """Content with its transfer encoding undone (local parts only)."""
        if self.local is None:
            raise ValueError("part content is not local")
        if self.content_type == "message/rfc822":
            inner = self.local.get_payload(0)
            return inner.as_bytes(policy=email.policy.SMTP) if isinstance(inner, EmailMessage) else b""
        return self.local.get_payload(decode=True) or b""

    @property
    def decoded_size_estimate(self) -> int:
        if self.local is not None:
            return len(self.decoded())
        return self.size * 3 // 4 if self.cte.lower() == "base64" else self.size


def _number(part: Part, section: str) -> None:
    part.section = section
    if part.is_multipart:
        for i, child in enumerate(part.children, 1):
            _number(child, f"{section}.{i}" if section else str(i))
    elif part.message is not None:
        inner = part.message
        _number(inner, section if inner.is_multipart else f"{section}.1")


def number_tree(root: Part) -> Part:
    _number(root, "" if root.is_multipart else "1")
    return root


def _from_email(msg: EmailMessage) -> Part:
    maintype, _, subtype = msg.get_content_type().partition("/")
    ctype_header = msg["Content-Type"]
    params = {k.lower(): str(v) for k, v in (ctype_header.params.items() if ctype_header is not None else ())}
    try:
        filename = msg.get_filename()
    except (ValueError, LookupError):
        filename = None
    content_id = msg["Content-ID"]
    part = Part(
        maintype,
        subtype,
        params,
        msg.get_content_disposition(),
        decode_header(filename) if filename else None,
        str(content_id).strip("<> ") if content_id else None,
        str(msg.get("Content-Transfer-Encoding", "7bit")).strip().lower(),
        local=msg,
    )
    if part.content_type == "message/rfc822":
        inner = msg.get_payload(0) if msg.is_multipart() else None
        if isinstance(inner, EmailMessage):
            part.message = _from_email(inner)
        return part
    if maintype == "multipart":
        if msg.is_multipart():
            part.children = [_from_email(p) for p in msg.iter_parts()]
        else:
            # A multipart without a usable boundary: keep its text as the body.
            part.maintype, part.subtype = "text", "plain"
    return part


def parse_message(raw: bytes) -> tuple[Headers, Part]:
    msg = email.message_from_bytes(raw, policy=POLICY)
    return Headers(list(msg.raw_items())), number_tree(_from_email(msg))


# imapclient hands BODYSTRUCTURE over as nested tuples of bytes/int/None
# (the top level and multipart children wrapped as BodyData, a tuple).


def _s(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1")
    return str(value)


def _params(value: Any) -> dict[str, str]:
    if not isinstance(value, (tuple, list)):
        return {}
    pairs = [(str(_s(value[i])).lower(), str(_s(value[i + 1]) or "")) for i in range(0, len(value) - 1, 2)]
    # RFC 2231 continuations and charsets, decoded by the stdlib.
    decoded = email.utils.decode_params([("", "")] + pairs)[1:]
    return {k: email.utils.collapse_rfc2231_value(v) for k, v in decoded}


def _disposition(value: Any) -> tuple[str | None, dict[str, str]]:
    if not isinstance(value, (tuple, list)) or not value:
        return None, {}
    kind = _s(value[0])
    return (kind.lower() if kind else None), (_params(value[1]) if len(value) > 1 else {})


def _filename(disp: dict[str, str], params: dict[str, str]) -> str | None:
    name = disp.get("filename") or params.get("name")
    return decode_header(name) if name else None


def from_bodystructure(value: Any) -> Part:
    return number_tree(_from_bs(value))


def _from_bs(value: Any) -> Part:
    if not isinstance(value, (tuple, list)) or not value:
        raise ValueError("bad BODYSTRUCTURE")
    if isinstance(value[0], (tuple, list)):
        if isinstance(value[0], list):  # BodyData: (children, subtype, ext…)
            children_raw, rest = value[0], list(value[1:])
        else:  # a raw tuple: children first
            i = 0
            while i < len(value) and isinstance(value[i], (tuple, list)):
                i += 1
            children_raw, rest = list(value[:i]), list(value[i:])
        children = [_from_bs(c) for c in children_raw]
        subtype = (_s(rest[0]) or "mixed").lower() if rest else "mixed"
        params = _params(rest[1]) if len(rest) > 1 else {}
        disp, disp_params = _disposition(rest[2]) if len(rest) > 2 else (None, {})
        if subtype == "rfc822":
            # gluon renders an encapsulated multipart message as a multipart
            # whose subtype is rfc822 and whose children are the inner
            # message's parts (no envelope, size or line count).
            inner = Part("multipart", "mixed", children=children)
            return Part("message", "rfc822", params, disp, _filename(disp_params, params), message=inner)
        return Part("multipart", subtype, params, disp, children=children)
    if len(value) < 7:
        raise ValueError("short BODYSTRUCTURE part")
    maintype = (_s(value[0]) or "text").lower()
    subtype = (_s(value[1]) or "plain").lower()
    params = _params(value[2])
    content_id = _s(value[3])
    size = int(value[6]) if isinstance(value[6], int) else 0
    ext, inner = 7, None
    if maintype == "text":
        ext = 8
    elif (maintype, subtype) == ("message", "rfc822") and len(value) >= 10:
        try:
            inner = _from_bs(value[8])
        except ValueError:
            inner = None
        ext = 10
    disp, disp_params = _disposition(value[ext + 1]) if len(value) > ext + 1 else (None, {})
    return Part(
        maintype,
        subtype,
        params,
        disp,
        _filename(disp_params, params),
        content_id.strip("<> ") if content_id else None,
        (_s(value[5]) or "7bit").lower(),
        size,
        message=inner,
    )


# ── what a message's body and attachments are ────────────────────────────
# (on the part tree, so the same answer comes from a local message and from
# a BODYSTRUCTURE; email's get_body/iter_attachments only see the former)

TEXT_TYPES = ("text/plain", "text/html")


def _is_body_text(part: Part) -> bool:
    return part.content_type in TEXT_TYPES and not part.is_attachment


def body_parts(node: Part) -> list[Part]:
    """The parts a reader would see as the body, in order."""
    if not node.is_multipart:
        return [node] if _is_body_text(node) else []
    children = node.children
    if node.subtype == "alternative":
        for want in TEXT_TYPES:
            for child in children:
                if child.content_type == want and not child.is_attachment:
                    return [child]
        for child in reversed(children):
            found = body_parts(child)
            if found:
                return found
        return []
    if node.subtype in ("related", "signed"):
        start = node.params.get("start", "").strip("<> ")
        for child in children:
            if start and child.content_id == start:
                return body_parts(child)
        return body_parts(children[0]) if children else []
    if node.subtype == "encrypted":
        return []
    out: list[Part] = []
    for child in children:
        if child.is_multipart:
            out.extend(body_parts(child))
        elif _is_body_text(child):
            out.append(child)
    return out


def html_alternative(root: Part, chosen: Part) -> Part | None:
    """The text/html sibling of a chosen text/plain inside an alternative."""
    for part in root.walk():
        if part.is_multipart and part.subtype == "alternative" and chosen in part.children:
            for child in part.children:
                if child.content_type == "text/html":
                    return child
    return None


def attachments(root: Part, body: list[Part]) -> list[Part]:
    """Every leaf that is not the body (message/rfc822 parts are one
    attachment each, not descended into)."""
    shown = {id(p) for p in body}
    out: list[Part] = []

    def visit(node: Part) -> None:
        if node.is_multipart:
            for child in node.children:
                # Other renderings of the body are not attachments.
                if node.subtype == "alternative" and child.content_type in TEXT_TYPES:
                    continue
                visit(child)
            return
        if id(node) in shown:
            return
        if node.content_type == "text/plain" and not node.filename and node.decoded_size_estimate == 0:
            return
        out.append(node)

    visit(root)
    return out


PGP_ARMOR = b"-----BEGIN PGP MESSAGE-----"
UNDECRYPTABLE_NOTE = b"This message could not be decrypted"


def is_undecryptable_text(decoded: bytes) -> bool:
    """Bridge's shape for a body it could not decrypt
    (pkg/message/build_custom.go): the armored message with a Comment."""
    head = decoded[:4096]
    return PGP_ARMOR in head and UNDECRYPTABLE_NOTE in head


def is_undecryptable_attachment(part: Part) -> bool:
    """Bridge renames an attachment it could not decrypt to <name>.pgp."""
    return bool(part.filename and part.filename.lower().endswith(".pgp")) and part.content_type == "application/octet-stream"


def is_pgp_mime_fallback(root: Part) -> bool:
    """Bridge's PGP/MIME fallback: the encrypted entity as it came."""
    return root.is_multipart and root.subtype == "encrypted"


def calendar_part(root: Part) -> Part | None:
    for part in root.walk():
        name = (part.filename or "").lower()
        if not part.is_multipart and (part.content_type in ("text/calendar", "application/ics") or name.endswith(".ics")):
            return part
    return None
