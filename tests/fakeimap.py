"""A scripted IMAP server that behaves like Proton Mail Bridge (gluon).

It records every command it receives (LOGIN's password redacted) so tests
can assert what each tool sent, and it reproduces Bridge's semantics and
quirks: SEARCH as a raw-byte substring match (no RFC 2047, no QP/base64
decoding), \\Noselect Folders/Labels parents, one message under different
UIDs in several mailboxes, UIDs newest to oldest, COPY/MOVE refused in
EXAMINE, non-PEEK fetches setting \\Seen, UIDPLUS codes, and scripted
faults: NO with no text, a drop in the middle of a FETCH without BYE,
a closed listener, a UIDVALIDITY bump.

Written independently of proton_mcp's own parser on purpose."""

from __future__ import annotations

import email
import email.policy
import email.utils
import itertools
import re
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ── modified UTF-7 (independent copy) ────────────────────────────────────


def mutf7_decode(s: str) -> str:
    import base64

    out, i = [], 0
    while i < len(s):
        if s[i] != "&":
            out.append(s[i])
            i += 1
            continue
        j = s.index("-", i)
        chunk = s[i + 1 : j]
        if not chunk:
            out.append("&")
        else:
            b = chunk.replace(",", "/")
            b += "=" * (-len(b) % 4)
            out.append(base64.b64decode(b).decode("utf-16-be"))
        i = j + 1
    return "".join(out)


def mutf7_encode(s: str) -> str:
    import base64

    out, buf = [], []

    def flush() -> None:
        if buf:
            raw = "".join(buf).encode("utf-16-be")
            out.append("&" + base64.b64encode(raw).decode().rstrip("=").replace("/", ",") + "-")
            buf.clear()

    for ch in s:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


# ── MIME, raw ─────────────────────────────────────────────────────────────


def split_header(raw: bytes) -> tuple[bytes, bytes]:
    m = re.search(rb"\r?\n\r?\n", raw)
    if not m:
        return raw, b""
    return raw[: m.end()], raw[m.end() :]


def header_fields(header: bytes) -> list[tuple[str, str]]:
    text = header.decode("latin-1")
    out: list[tuple[str, str]] = []
    for line in re.split(r"\r?\n", text):
        if not line:
            continue
        if line[0] in " \t" and out:
            out[-1] = (out[-1][0], out[-1][1] + " " + line.strip())
        elif ":" in line:
            k, v = line.split(":", 1)
            out.append((k.strip(), v.strip()))
    return out


def header_get(fields: list[tuple[str, str]], name: str) -> str | None:
    for k, v in fields:
        if k.lower() == name.lower():
            return v
    return None


@dataclass
class Node:
    header: bytes
    body: bytes
    maintype: str
    subtype: str
    params: list[tuple[str, str]]
    children: list[Node] = field(default_factory=list)
    inner: Node | None = None


def parse_node(raw: bytes, default: str = "text/plain") -> Node:
    header, body = split_header(raw)
    msg = email.message_from_bytes(header + b"\r\n", policy=email.policy.compat32)
    ctype = msg.get_content_type() if msg.get("Content-Type") else default
    maintype, _, subtype = ctype.partition("/")
    params = [(k, v if isinstance(v, str) else email.utils.collapse_rfc2231_value(v)) for k, v in (msg.get_params() or [])[1:]]
    node = Node(header, body, maintype, subtype, params)
    if maintype == "multipart":
        boundary = msg.get_boundary()
        if boundary:
            delim = re.compile(rb"(?:^|\r?\n)--" + re.escape(boundary.encode()) + rb"(--)?[ \t]*(?:\r?\n|$)")
            pieces = []
            pos = None
            for m in delim.finditer(body):
                if pos is not None:
                    pieces.append(body[pos : m.start()])
                if m.group(1):
                    pos = None
                    break
                pos = m.end()
            if pos is not None:
                pieces.append(body[pos:])
            child_default = "message/rfc822" if subtype == "digest" else "text/plain"
            node.children = [parse_node(p, child_default) for p in pieces]
    elif ctype == "message/rfc822":
        node.inner = parse_node(body)
    return node


def find_section(root: Node, path: list[int]) -> Node:
    node = root
    for depth, n in enumerate(path):
        if depth > 0 and node.inner is not None:
            node = node.inner  # into an encapsulated message
        if node.children:
            node = node.children[n - 1]
        elif n != 1:  # a single-part body is its own part 1
            raise KeyError("no such part")
    return node


def imap_string(value: str | bytes | None) -> bytes:
    if value is None:
        return b"NIL"
    raw = value.encode("utf-8") if isinstance(value, str) else value
    if re.search(rb'[\r\n"\\\x80-\xff]', raw):
        return b"{%d}\r\n" % len(raw) + raw
    return b'"' + raw + b'"'


def _addr_list(value: str | None) -> bytes:
    if not value:
        return b"NIL"
    items = []
    for name, addr in email.utils.getaddresses([value]):
        if not addr:
            continue
        mailbox, _, host = addr.partition("@")
        items.append(b"(" + imap_string(name or None) + b" NIL " + imap_string(mailbox) + b" " + imap_string(host or None) + b")")
    return b"(" + b"".join(items) + b")" if items else b"NIL"


def envelope(header: bytes) -> bytes:
    f = header_fields(header)
    frm = header_get(f, "From")
    sender = header_get(f, "Sender") or frm
    reply_to = header_get(f, "Reply-To") or frm
    parts = [
        imap_string(header_get(f, "Date")),
        imap_string(header_get(f, "Subject")),
        _addr_list(frm),
        _addr_list(sender),
        _addr_list(reply_to),
        _addr_list(header_get(f, "To")),
        _addr_list(header_get(f, "Cc")),
        _addr_list(header_get(f, "Bcc")),
        imap_string(header_get(f, "In-Reply-To")),
        imap_string(header_get(f, "Message-ID")),
    ]
    return b"(" + b" ".join(parts) + b")"


def _params(params: list[tuple[str, str]]) -> bytes:
    if not params:
        return b"NIL"
    return b"(" + b" ".join(imap_string(k.upper()) + b" " + imap_string(v) for k, v in params) + b")"


def bodystructure(node: Node) -> bytes:
    msg = email.message_from_bytes(node.header + b"\r\n", policy=email.policy.compat32)
    disp = msg.get_content_disposition()
    disp_bytes = b"NIL"
    if disp:
        fn = msg.get_param("filename", header="content-disposition")
        dp = [("FILENAME", email.utils.collapse_rfc2231_value(fn))] if fn else []
        disp_bytes = b"(" + imap_string(disp.upper()) + b" " + _params(dp) + b")"
    if node.maintype == "multipart":
        return (
            b"("
            + b"".join(bodystructure(c) for c in node.children)
            + b" "
            + imap_string(node.subtype.upper())
            + b" "
            + _params(node.params)
            + b" "
            + disp_bytes
            + b" NIL NIL)"
        )
    cte = (msg.get("Content-Transfer-Encoding") or "7bit").strip().upper()
    cid = msg.get("Content-ID")
    fields = [
        imap_string(node.maintype.upper()),
        imap_string(node.subtype.upper()),
        _params(node.params),
        imap_string(cid.strip() if cid else None),
        b"NIL",
        imap_string(cte),
        str(len(node.body)).encode(),
    ]
    if node.maintype == "text":
        fields.append(str(node.body.count(b"\n")).encode())
    if node.maintype == "message" and node.subtype == "rfc822" and node.inner is not None:
        fields += [envelope(node.inner.header), bodystructure(node.inner), str(node.body.count(b"\n")).encode()]
    fields += [b"NIL", disp_bytes, b"NIL", b"NIL"]
    return b"(" + b" ".join(fields) + b")"


# ── the store ─────────────────────────────────────────────────────────────


@dataclass
class Message:
    raw: bytes
    date: int
    key: int  # one Proton message, whatever mailboxes it is in


@dataclass
class Entry:
    msg: Message
    flags: set[str]


@dataclass
class Box:
    name: str
    attrs: tuple[str, ...]
    uidvalidity: int
    uidnext: int = 1
    entries: dict[int, Entry] = field(default_factory=dict)

    @property
    def selectable(self) -> bool:
        return "\\Noselect" not in self.attrs

    def sorted_uids(self) -> list[int]:
        return sorted(self.entries)


SYSTEM = [
    ("INBOX", ()),
    ("Drafts", ("\\Drafts",)),
    ("Sent", ("\\Sent",)),
    ("Starred", ("\\Flagged",)),
    ("Archive", ("\\Archive",)),
    ("Spam", ("\\Junk",)),
    ("Trash", ("\\Trash",)),
    ("All Mail", ("\\All",)),
    ("Folders", ("\\Noselect",)),
    ("Labels", ("\\Noselect",)),
]


class Store:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.boxes: dict[str, Box] = {}
        self._keys = itertools.count(1)
        self._validity = itertools.count(1000)
        for name, attrs in SYSTEM:
            self.boxes[name] = Box(name, attrs, next(self._validity))

    def add(self, mailbox: str, raw: bytes, date: int, flags: tuple[str, ...] = (), also_in: tuple[str, ...] = ()) -> Message:
        with self.lock:
            msg = Message(raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"), date, next(self._keys))
            for name in (mailbox, *also_in):
                self.put(name, msg, set(flags))
            return msg

    def put(self, mailbox: str, msg: Message, flags: set[str]) -> int:
        box = self.boxes[mailbox]
        uid = box.uidnext
        box.uidnext += 1
        box.entries[uid] = Entry(msg, set(flags))
        return uid

    def uid_of(self, mailbox: str, msg: Message) -> int:
        for uid, e in self.boxes[mailbox].entries.items():
            if e.msg is msg:
                return uid
        raise KeyError(mailbox)

    def create(self, name: str) -> None:
        self.boxes[name] = Box(name, (), next(self._validity))

    def bump_uidvalidity(self, mailbox: str) -> None:
        """A resync: new UIDVALIDITY, UIDs reassigned newest to oldest."""
        with self.lock:
            box = self.boxes[mailbox]
            entries = sorted(box.entries.values(), key=lambda e: -e.msg.date)
            box.uidvalidity = next(self._validity)
            box.entries = {}
            box.uidnext = 1
            for e in entries:
                box.entries[box.uidnext] = e
                box.uidnext += 1

    def flags(self, mailbox: str, msg: Message) -> set[str]:
        return self.boxes[mailbox].entries[self.uid_of(mailbox, msg)].flags


# ── the protocol ──────────────────────────────────────────────────────────

CAPS_PRE = b"IMAP4rev1 STARTTLS IDLE ID AUTH=PLAIN"
CAPS_POST = b"IMAP4rev1 STARTTLS IDLE ID AUTH=PLAIN UNSELECT UIDPLUS MOVE"
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


class Lit(bytes):
    pass


def tokenize(data: bytes, literals: list[bytes]) -> list[Any]:
    """Atoms (with [..] sections), quoted strings, literals (\\x00N\\x00), lists."""
    stack: list[list[Any]] = [[]]
    i = 0
    while i < len(data):
        c = data[i : i + 1]
        if c in b" ":
            i += 1
        elif c == b"(":
            stack.append([])
            i += 1
        elif c == b")":
            done = stack.pop()
            stack[-1].append(done)
            i += 1
        elif c == b'"':
            j = i + 1
            buf = bytearray()
            while data[j : j + 1] != b'"':
                if data[j : j + 1] == b"\\":
                    j += 1
                buf += data[j : j + 1]
                j += 1
            stack[-1].append(bytes(buf).decode("utf-8", "replace"))
            i = j + 1
        elif c == b"\x00":
            j = data.index(b"\x00", i + 1)
            stack[-1].append(Lit(literals[int(data[i + 1 : j])]))
            i = j + 1
        else:
            j = i
            depth = 0
            while j < len(data):
                ch = data[j : j + 1]
                if ch == b"[":
                    depth += 1
                elif ch == b"]":
                    depth -= 1
                elif depth == 0 and ch in b" ()":
                    break
                j += 1
            stack[-1].append(data[i:j].decode("latin-1"))
            i = j
    return stack[0]


def parse_uidset(text: str, box: Box) -> list[int]:
    out: list[int] = []
    top = max(box.entries) if box.entries else 0
    for item in text.split(","):
        if ":" in item:
            a, b = item.split(":")
            lo = top if a == "*" else int(a)
            hi = top if b == "*" else int(b)
            lo, hi = min(lo, hi), max(lo, hi)
            out.extend(u for u in box.sorted_uids() if lo <= u <= hi)
        else:
            u = top if item == "*" else int(item)
            if u in box.entries:
                out.append(u)
    return sorted(set(out))


def internaldate(epoch: int) -> str:
    d = datetime.fromtimestamp(epoch, UTC)
    return f"{d.day:02d}-{MONTHS[d.month - 1]}-{d.year} {d:%H:%M:%S} +0000"


def parse_date(text: str) -> int:
    day, mon, year = text.split("-")
    return int(datetime(int(year), MONTHS.index(mon.capitalize()) + 1, int(day), tzinfo=UTC).timestamp())


class Fault:
    def __init__(self, command: str, action: str, count: int = 1) -> None:
        self.command, self.action, self.count = command.upper(), action, count


class Handler(socketserver.StreamRequestHandler):
    server: FakeIMAP

    def setup(self) -> None:
        srv = self.server
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if srv.implicit_tls:
            self.request = srv.tls.wrap_socket(self.request, server_side=True)
        super().setup()
        self.session = next(srv.sessions)
        self.authed = False
        self.selected: Box | None = None
        self.readonly = True

    def out(self, data: bytes) -> None:
        self.wfile.write(data)
        self.wfile.flush()

    def handle(self) -> None:
        self.out(b"* OK [CAPABILITY " + CAPS_PRE + b"] Proton Mail Bridge (fake) ready\r\n")
        while True:
            try:
                line = self.rfile.readline(1 << 20)
            except (OSError, ssl.SSLError):
                return
            if not line:
                return
            literals: list[bytes] = []
            while True:
                m = re.search(rb"\{(\d+)(\+?)\}\r\n$", line)
                if not m:
                    break
                if not m.group(2):
                    self.out(b"+ Ready\r\n")
                n = int(m.group(1))
                data = self.rfile.read(n)
                literals.append(data)
                line = line[: m.start()] + b"\x00%d\x00" % (len(literals) - 1) + self.rfile.readline(1 << 20)
            line = line.rstrip(b"\r\n")
            try:
                toks = tokenize(line, literals)
            except (ValueError, IndexError):
                self.out(b"* BAD parse error\r\n")
                continue
            if len(toks) < 2:
                self.out(b"* BAD missing command\r\n")
                continue
            tag, name, args = str(toks[0]), str(toks[1]).upper(), toks[2:]
            self.server.record(self.session, name, args, line)
            if self.server.inject(self, tag, name, args):
                if self.server.dropped:
                    return
                continue
            try:
                keep = getattr(self, "cmd_" + name.replace(".", "_"), self.cmd_unknown)(tag, args)
            except (KeyError, ValueError, IndexError) as exc:
                self.out(f"{tag} BAD {type(exc).__name__}\r\n".encode())
                continue
            if keep is False:
                return

    # ── commands ─────────────────────────────────────────────────────────

    def cmd_unknown(self, tag: str, args: list[Any]) -> None:
        self.out(f"{tag} BAD unknown command\r\n".encode())

    def cmd_CAPABILITY(self, tag: str, args: list[Any]) -> None:
        self.out(b"* CAPABILITY " + (CAPS_POST if self.authed else CAPS_PRE) + b"\r\n")
        self.out(f"{tag} OK CAPABILITY\r\n".encode())

    def cmd_NOOP(self, tag: str, args: list[Any]) -> None:
        self.out(f"{tag} OK NOOP\r\n".encode())

    def cmd_ID(self, tag: str, args: list[Any]) -> None:
        self.out(b'* ID ("name" "fake")\r\n' + f"{tag} OK ID\r\n".encode())

    def cmd_STARTTLS(self, tag: str, args: list[Any]) -> bool | None:
        self.out(f"{tag} OK begin TLS\r\n".encode())
        self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        self.rfile = self.request.makefile("rb")
        self.wfile = self.request.makefile("wb")
        return None

    def cmd_LOGOUT(self, tag: str, args: list[Any]) -> bool:
        self.out(b"* BYE\r\n" + f"{tag} OK LOGOUT\r\n".encode())
        return False

    def cmd_LOGIN(self, tag: str, args: list[Any]) -> None:
        user, password = str(args[0]), str(args[1])
        if user.lower() in [u.lower() for u in self.server.users] and password == self.server.password:
            self.authed = True
            self.out(f"{tag} OK [CAPABILITY ".encode() + CAPS_POST + b"] LOGIN\r\n")
        else:
            self.out(f"{tag} NO [AUTHENTICATIONFAILED] invalid credentials\r\n".encode())

    def _need_auth(self, tag: str) -> bool:
        if not self.authed:
            self.out(f"{tag} BAD not authenticated\r\n".encode())
            return False
        return True

    def cmd_LIST(self, tag: str, args: list[Any]) -> None:
        if not self._need_auth(tag):
            return
        with self.server.store.lock:
            for box in self.server.store.boxes.values():
                if box.name == "All Mail" and not self.server.show_all_mail:
                    continue
                attrs = " ".join(box.attrs)
                self.out(f'* LIST ({attrs}) "/" "{mutf7_encode(box.name)}"\r\n'.encode())
        self.out(f"{tag} OK LIST\r\n".encode())

    def _box(self, arg: Any) -> Box | None:
        return self.server.store.boxes.get(mutf7_decode(str(arg)))

    def cmd_STATUS(self, tag: str, args: list[Any]) -> None:
        if not self._need_auth(tag):
            return
        box = self._box(args[0])
        if box is None or not box.selectable:
            self.out(f"{tag} NO no such mailbox\r\n".encode())
            return
        items = []
        for item in args[1]:
            item = item.upper()
            value = {
                "MESSAGES": len(box.entries),
                "UNSEEN": sum(1 for e in box.entries.values() if "\\Seen" not in e.flags),
                "UIDVALIDITY": box.uidvalidity,
                "UIDNEXT": box.uidnext,
                "RECENT": 0,
            }[item]
            items.append(f"{item} {value}")
        self.out(f'* STATUS "{mutf7_encode(box.name)}" ({" ".join(items)})\r\n'.encode())
        self.out(f"{tag} OK STATUS\r\n".encode())

    def _open(self, tag: str, args: list[Any], readonly: bool) -> None:
        if not self._need_auth(tag):
            return
        box = self._box(args[0])
        if box is None or not box.selectable:
            self.selected = None
            self.out(f"{tag} NO no such mailbox\r\n".encode())
            return
        self.selected, self.readonly = box, readonly
        self.out(b"* FLAGS (\\Seen \\Flagged \\Deleted \\Draft \\Answered)\r\n")
        self.out(b"* OK [PERMANENTFLAGS (\\Seen \\Flagged \\Deleted \\Draft \\Answered)] Flags\r\n")
        self.out(f"* {len(box.entries)} EXISTS\r\n* 0 RECENT\r\n".encode())
        self.out(f"* OK [UIDVALIDITY {box.uidvalidity}] UIDs\r\n* OK [UIDNEXT {box.uidnext}] next\r\n".encode())
        mode = "READ-ONLY" if readonly else "READ-WRITE"
        self.out(f"{tag} OK [{mode}] {'EXAMINE' if readonly else 'SELECT'}\r\n".encode())

    def cmd_SELECT(self, tag: str, args: list[Any]) -> None:
        self._open(tag, args, False)

    def cmd_EXAMINE(self, tag: str, args: list[Any]) -> None:
        self._open(tag, args, True)

    def cmd_UNSELECT(self, tag: str, args: list[Any]) -> None:
        self.selected = None
        self.out(f"{tag} OK UNSELECT\r\n".encode())

    def cmd_CLOSE(self, tag: str, args: list[Any]) -> None:
        if self.selected is not None and not self.readonly:
            self._expunge(None)
        self.selected = None
        self.out(f"{tag} OK CLOSE\r\n".encode())

    def cmd_EXPUNGE(self, tag: str, args: list[Any]) -> None:
        if self.selected is None or self.readonly:
            self.out(f"{tag} NO read-only\r\n".encode())
            return
        self._expunge(None)
        self.out(f"{tag} OK EXPUNGE\r\n".encode())

    def _expunge(self, uids: list[int] | None) -> None:
        box = self.selected
        assert box is not None
        with self.server.store.lock:
            seqs = []
            for seq, uid in enumerate(box.sorted_uids(), 1):
                e = box.entries[uid]
                if "\\Deleted" in e.flags and (uids is None or uid in uids):
                    seqs.append((seq, uid))
            for seq, uid in reversed(seqs):
                del box.entries[uid]
                self.out(f"* {seq} EXPUNGE\r\n".encode())
            self.server.expunged.extend((box.name, uid) for _, uid in seqs)

    def cmd_UID(self, tag: str, args: list[Any]) -> bool | None:
        sub = str(args[0]).upper()
        if self.selected is None:
            self.out(f"{tag} BAD no mailbox selected\r\n".encode())
            return None
        return getattr(self, "uid_" + sub)(tag, args[1:])

    # SEARCH with Bridge's semantics: substring of raw bytes.
    def _match(self, entry: Entry, keys: list[Any], pos: int, box: Box, uid: int) -> tuple[bool, int]:
        key = keys[pos]
        if isinstance(key, list):
            ok = True
            p = 0
            while p < len(key):
                r, p = self._match(entry, key, p, box, uid)
                ok = ok and r
            return ok, pos + 1
        k = str(key).upper()
        raw = entry.msg.raw
        header, body = split_header(raw)
        fields = header_fields(header)
        flags = entry.flags
        simple = {
            "ALL": True,
            "SEEN": "\\Seen" in flags,
            "UNSEEN": "\\Seen" not in flags,
            "FLAGGED": "\\Flagged" in flags,
            "UNFLAGGED": "\\Flagged" not in flags,
            "DELETED": "\\Deleted" in flags,
            "UNDELETED": "\\Deleted" not in flags,
            "DRAFT": "\\Draft" in flags,
            "UNDRAFT": "\\Draft" not in flags,
            "ANSWERED": "\\Answered" in flags,
            "UNANSWERED": "\\Answered" not in flags,
        }
        if k in simple:
            return simple[k], pos + 1
        if k in ("SINCE", "BEFORE", "ON"):
            d = parse_date(str(keys[pos + 1]))
            day = entry.msg.date - entry.msg.date % 86400
            return {"SINCE": day >= d, "BEFORE": day < d, "ON": day == d}[k], pos + 2
        if k in ("FROM", "TO", "CC", "BCC", "SUBJECT"):
            v = header_get(fields, k.capitalize() if k != "BCC" else "Bcc") or ""
            return str(keys[pos + 1]).lower() in v.lower(), pos + 2
        if k == "HEADER":
            v = header_get(fields, str(keys[pos + 1])) or ""
            return str(keys[pos + 2]).lower() in v.lower(), pos + 3
        if k == "BODY":
            return str(keys[pos + 1]).lower().encode() in body.lower(), pos + 2
        if k == "TEXT":
            return str(keys[pos + 1]).lower().encode() in raw.lower(), pos + 2
        if k == "UID":
            return uid in parse_uidset(str(keys[pos + 1]), box), pos + 2
        if k == "NOT":
            r, p = self._match(entry, keys, pos + 1, box, uid)
            return not r, p
        if k == "OR":
            a, p = self._match(entry, keys, pos + 1, box, uid)
            b, p = self._match(entry, keys, p, box, uid)
            return a or b, p
        if k == "CHARSET":
            return True, pos + 2
        raise ValueError(f"search key {k}")

    def uid_SEARCH(self, tag: str, args: list[Any]) -> None:
        box = self.selected
        assert box is not None
        if not box.entries and any(str(a).upper() == "UID" for a in args):
            # gluon: a UID key cannot be resolved in an empty mailbox
            self.out(f"{tag} NO no such message\r\n".encode())
            return
        hits = []
        with self.server.store.lock:
            for uid in box.sorted_uids():
                entry = box.entries[uid]
                ok, p = True, 0
                while p < len(args):
                    r, p = self._match(entry, args, p, box, uid)
                    ok = ok and r
                if ok:
                    hits.append(uid)
        self.out(b"* SEARCH" + b"".join(b" %d" % u for u in hits) + b"\r\n")
        self.out(f"{tag} OK SEARCH\r\n".encode())

    def _section(self, msg: Message, spec: str) -> bytes:
        raw = msg.raw
        root = parse_node(raw)
        header, body = split_header(raw)
        m = re.fullmatch(r"((?:\d+\.)*\d+)?\.?(.*)", spec)
        assert m
        part, text = m.group(1), m.group(2).upper()
        if part is None:
            node_header, node_body = header, body
        else:
            node = find_section(root, [int(x) for x in part.split(".")])
            if text in ("HEADER", "TEXT") or text.startswith("HEADER.FIELDS"):
                inner = node.inner if node.inner is not None else node
                node_header, node_body = inner.header, inner.body
            elif text == "MIME":
                return node.header
            else:
                if node is root and not root.children:
                    return body
                return node.body
        if text == "":
            return raw if part is None else node_body
        if text == "HEADER":
            return node_header
        if text == "TEXT":
            return node_body
        fm = re.fullmatch(r"HEADER\.FIELDS(\.NOT)? \((.*)\)", m.group(2), re.I)
        assert fm
        names = {n.lower() for n in fm.group(2).split()}
        lines = []
        for line in re.split(rb"\r\n(?![ \t])", node_header.rstrip(b"\r\n")):
            name = line.split(b":", 1)[0].decode("latin-1").strip().lower()
            if (name in names) != bool(fm.group(1)):
                lines.append(line + b"\r\n")
        return b"".join(lines) + b"\r\n"

    def uid_FETCH(self, tag: str, args: list[Any]) -> bool | None:
        box = self.selected
        assert box is not None
        uids = parse_uidset(str(args[0]), box)
        items = args[1] if isinstance(args[1], list) else [args[1]]
        for uid in uids:
            with self.server.store.lock:
                entry = box.entries.get(uid)
            if entry is None:
                continue
            seq = box.sorted_uids().index(uid) + 1
            parts: list[bytes] = []
            seen_now = False
            for item in items:
                name = str(item)
                up = name.upper()
                if up == "UID":
                    parts.append(b"UID %d" % uid)
                elif up == "FLAGS":
                    parts.append(b"FLAGS (" + " ".join(sorted(entry.flags)).encode() + b")")
                elif up == "INTERNALDATE":
                    parts.append(b'INTERNALDATE "' + internaldate(entry.msg.date).encode() + b'"')
                elif up == "RFC822.SIZE":
                    parts.append(b"RFC822.SIZE %d" % len(entry.msg.raw))
                elif up == "ENVELOPE":
                    parts.append(b"ENVELOPE " + envelope(split_header(entry.msg.raw)[0]))
                elif up == "BODYSTRUCTURE":
                    parts.append(b"BODYSTRUCTURE " + bodystructure(parse_node(entry.msg.raw)))
                elif up in ("RFC822", "RFC822.TEXT", "RFC822.HEADER"):
                    data = {
                        "RFC822": entry.msg.raw,
                        "RFC822.TEXT": split_header(entry.msg.raw)[1],
                        "RFC822.HEADER": split_header(entry.msg.raw)[0],
                    }[up]
                    parts.append(up.encode() + b" {%d}\r\n" % len(data) + data)
                    seen_now = seen_now or up != "RFC822.HEADER"
                else:
                    m = re.fullmatch(r"BODY(\.PEEK)?\[(.*)\](?:<(\d+)\.(\d+)>)?", name, re.I | re.S)
                    if not m:
                        raise ValueError(f"fetch item {name}")
                    data = self._section(entry.msg, m.group(2))
                    label = f"BODY[{m.group(2)}]"
                    if m.group(3) is not None:
                        start, length = int(m.group(3)), int(m.group(4))
                        data = data[start : start + length]
                        label += f"<{start}>"
                    parts.append(label.encode() + b" {%d}\r\n" % len(data) + data)
                    seen_now = seen_now or not m.group(1)
            if seen_now and not self.readonly and "\\Seen" not in entry.flags:
                entry.flags.add("\\Seen")
                parts.append(b"FLAGS (" + " ".join(sorted(entry.flags)).encode() + b")")
            if "UID" not in [str(i).upper() for i in items]:
                parts.append(b"UID %d" % uid)
            line = b"* %d FETCH (" % seq + b" ".join(parts) + b")\r\n"
            if self.server.drop_mid_fetch:
                # Bridge drops sockets without BYE (Proton API outage).
                self.server.drop_mid_fetch = False
                self.out(line[: max(10, len(line) // 2)])
                self.request.close()
                return False
            self.out(line)
        self.out(f"{tag} OK FETCH\r\n".encode())
        return None

    def _writable(self, tag: str) -> bool:
        if self.readonly:
            self.out(f"{tag} NO mailbox is read-only\r\n".encode())
            return False
        return True

    def uid_STORE(self, tag: str, args: list[Any]) -> None:
        if not self._writable(tag):
            return
        box = self.selected
        assert box is not None
        op = str(args[1]).upper()
        flags = {str(f) for f in (args[2] if isinstance(args[2], list) else [args[2]])}
        for uid in parse_uidset(str(args[0]), box):
            e = box.entries[uid]
            if op.startswith("+"):
                e.flags |= flags
            elif op.startswith("-"):
                e.flags -= flags
            else:
                e.flags = set(flags)
            if not op.endswith(".SILENT"):
                seq = box.sorted_uids().index(uid) + 1
                self.out(b"* %d FETCH (UID %d FLAGS (" % (seq, uid) + " ".join(sorted(e.flags)).encode() + b"))\r\n")
        self.out(f"{tag} OK STORE\r\n".encode())

    def _copy(self, tag: str, args: list[Any], move: bool) -> None:
        if not self._writable(tag):
            return
        box = self.selected
        assert box is not None
        dest = self._box(args[1])
        if dest is None or not dest.selectable:
            self.out(f"{tag} NO [TRYCREATE] no such mailbox\r\n".encode())
            return
        src_uids, dst_uids = [], []
        with self.server.store.lock:
            for uid in parse_uidset(str(args[0]), box):
                e = box.entries[uid]
                existing = [u for u, d in dest.entries.items() if d.msg is e.msg]
                new = existing[0] if existing else self.server.store.put(dest.name, e.msg, set(e.flags) - {"\\Deleted"})
                src_uids.append(uid)
                dst_uids.append(new)
            code = f"[COPYUID {dest.uidvalidity} {','.join(map(str, src_uids))} {','.join(map(str, dst_uids))}]"
            if move:
                self.out(f"* OK {code} moved\r\n".encode())
                for uid in reversed(src_uids):
                    seq = box.sorted_uids().index(uid) + 1
                    del box.entries[uid]
                    self.out(f"* {seq} EXPUNGE\r\n".encode())
                self.out(f"{tag} OK MOVE\r\n".encode())
            else:
                self.out(f"{tag} OK {code} COPY\r\n".encode() if src_uids else f"{tag} OK COPY\r\n".encode())

    def uid_COPY(self, tag: str, args: list[Any]) -> None:
        self._copy(tag, args, False)

    def uid_MOVE(self, tag: str, args: list[Any]) -> None:
        self._copy(tag, args, True)

    def uid_EXPUNGE(self, tag: str, args: list[Any]) -> None:
        if not self._writable(tag):
            return
        box = self.selected
        assert box is not None
        self._expunge(parse_uidset(str(args[0]), box))
        self.out(f"{tag} OK EXPUNGE\r\n".encode())

    def cmd_APPEND(self, tag: str, args: list[Any]) -> None:
        if not self._need_auth(tag):
            return
        box = self._box(args[0])
        if box is None or not box.selectable:
            self.out(f"{tag} NO [TRYCREATE] no such mailbox\r\n".encode())
            return
        flags: set[str] = set()
        literal = args[-1]
        if isinstance(args[1], list):
            flags = {str(f) for f in args[1]}
        # gluon's rfcvalidation: Date and From required, Sender for a multi-address From.
        fields = header_fields(split_header(bytes(literal))[0])
        senders = email.utils.getaddresses([header_get(fields, "From") or ""])
        if (
            not header_get(fields, "Date")
            or not header_get(fields, "From")
            or (len(senders) > 1 and not header_get(fields, "Sender"))
        ):
            self.out(f"{tag} BAD invalid rfc5322 message\r\n".encode())
            return
        msg = Message(bytes(literal), int(time.time()), next(self.server.store._keys))
        with self.server.store.lock:
            uid = self.server.store.put(box.name, msg, flags)
        self.server.appended.append((box.name, uid, bytes(literal), flags))
        self.out(f"{tag} OK [APPENDUID {box.uidvalidity} {uid}] APPEND\r\n".encode())

    def _bridge_name_ok(self, name: str) -> bool:
        if name.startswith("Folders/") and len(name) > 8:
            parent = name.rsplit("/", 1)[0]
            return parent == "Folders" or parent in self.server.store.boxes
        return name.startswith("Labels/") and len(name) > 7 and "/" not in name[7:]

    def cmd_CREATE(self, tag: str, args: list[Any]) -> None:
        name = mutf7_decode(str(args[0]))
        if not self._bridge_name_ok(name) or name in self.server.store.boxes:
            self.out(f"{tag} NO operation not allowed\r\n".encode())
            return
        self.server.store.create(name)
        self.out(f"{tag} OK CREATE\r\n".encode())

    def cmd_DELETE(self, tag: str, args: list[Any]) -> None:
        name = mutf7_decode(str(args[0]))
        if name not in self.server.store.boxes or not (name.startswith("Folders/") or name.startswith("Labels/")):
            self.out(f"{tag} NO operation not allowed\r\n".encode())
            return
        for other in list(self.server.store.boxes):
            if other == name or other.startswith(name + "/"):
                del self.server.store.boxes[other]
        self.out(f"{tag} OK DELETE\r\n".encode())

    def cmd_RENAME(self, tag: str, args: list[Any]) -> None:
        old, new = mutf7_decode(str(args[0])), mutf7_decode(str(args[1]))
        boxes = self.server.store.boxes
        if old not in boxes or new in boxes or old[:7] != new[:7] or not self._bridge_name_ok(new):
            self.out(f"{tag} NO operation not allowed\r\n".encode())
            return
        for name in list(boxes):
            if name == old or name.startswith(old + "/"):
                box = boxes.pop(name)
                box.name = new + name[len(old) :]
                boxes[box.name] = box
        self.out(f"{tag} OK RENAME\r\n".encode())


class FakeIMAP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, store: Store, tls: ssl.SSLContext, password: str, users: list[str], implicit_tls: bool = True) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.store = store
        self.tls = tls
        self.password = password
        self.users = users
        self.implicit_tls = implicit_tls
        self.sessions = itertools.count(1)
        self.commands: list[tuple[int, str, str]] = []
        self.appended: list[tuple[str, int, bytes, set[str]]] = []
        self.expunged: list[tuple[str, int]] = []
        self.faults: list[Fault] = []
        self.drop_mid_fetch = False
        self.dropped = False
        self.show_all_mail = True
        self.hang_seconds = 3.0
        self._lock = threading.Lock()
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server_address[1]

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # refused handshakes and dropped clients are what the tests provoke

    def start(self) -> FakeIMAP:
        self.thread.start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()

    def refuse(self) -> int:
        """Close the listener: connects now get ECONNREFUSED. Returns the port."""
        port = self.port
        self.shutdown()
        self.server_close()
        return port

    def record(self, session: int, name: str, args: list[Any], line: bytes) -> None:
        text = line.decode("latin-1")
        if name == "LOGIN":
            text = re.sub(r"^(\S+ LOGIN \S+) .*$", r"\1 <redacted>", text)
        text = re.sub(r"\x00\d+\x00", "{literal}", text)
        with self._lock:
            self.commands.append((session, name, text.split(" ", 1)[1] if " " in text else text))

    def clear(self) -> None:
        with self._lock:
            self.commands.clear()
            self.appended.clear()
            self.expunged.clear()

    def sent(self) -> list[str]:
        """Each recorded command as 'NAME args…' (tag dropped)."""
        with self._lock:
            return [c for _, _, c in self.commands]

    def fail(self, command: str, action: str, count: int = 1) -> None:
        self.faults.append(Fault(command, action, count))

    def inject(self, h: Handler, tag: str, name: str, args: list[Any]) -> bool:
        self.dropped = False
        full = name + (" " + str(args[0]).upper() if name == "UID" and args else "")
        for f in self.faults:
            if f.count > 0 and full == f.command:
                f.count -= 1
                if f.action == "no-empty":
                    h.out(f"{tag} NO \r\n".encode())
                elif f.action == "no-bare":
                    h.out(f"{tag} NO\r\n".encode())
                elif f.action == "bad":
                    h.out(f"{tag} BAD\r\n".encode())
                elif f.action == "drop":
                    self.dropped = True
                    h.request.close()
                elif f.action == "drop-mid-fetch":
                    self.drop_mid_fetch = True
                    return False
                elif f.action == "hang":
                    time.sleep(self.hang_seconds)
                    self.dropped = True
                    h.request.close()
                return True
        return False


def tls_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
