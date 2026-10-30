"""MIME for drafts and for the one sent message (an invitation reply).

Built with email.message.EmailMessage under the SMTP policy: header values
with CR or LF are rejected by the library, addresses go through
headerregistry.Address (which validates them), and nothing here ever
writes an X-Pm-* header (gluon treats an APPEND carrying X-Pm-Gluon-Id as
a copy of an existing message)."""

from __future__ import annotations

import email.policy
import email.utils
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.headerregistry import Address as HAddress
from email.message import EmailMessage

from .errors import InvalidArgument, Refused
from .mime import Address, Headers, message_ids, normalize_address

MAX_BODY = 100_000
MAX_SUBJECT = 900
MAX_RECIPIENTS = 100
MAX_QUOTE = 20_000
MAX_REFERENCES = 20
INTERNAL_REF = re.compile(r"@protonmail\.internalid$", re.I)
_ADDR = re.compile(r"[^@\s<>()\[\],;:\"\\]+@[^@\s<>()\[\],;:\"\\]+\.[^@\s<>()\[\],;:\"\\]+")


def parse_recipients(values: list[str] | None, field: str) -> list[Address]:
    out: list[Address] = []
    for value in values or []:
        if not isinstance(value, str) or re.search(r"[\r\n\x00]", value):
            raise InvalidArgument(f"{field}: bad recipient")
        parsed = email.utils.getaddresses([value])
        if not parsed or not all(addr for _, addr in parsed):
            raise InvalidArgument(f"{field}: cannot read {value!r} as an address")
        for name, addr in parsed:
            if not _ADDR.fullmatch(addr):
                raise InvalidArgument(f"{field}: {addr!r} is not an address")
            out.append(Address(name.strip(), addr))
    return dedupe(out)


def dedupe(addrs: list[Address], exclude: set[str] | None = None) -> list[Address]:
    seen = set(exclude or ())
    out = []
    for a in addrs:
        key = normalize_address(a.address)
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out


def choose_from(requested: str | None, account: tuple[str, ...], default: str) -> str:
    """The From address: one of the account's, never anything else."""
    if requested is None or requested == "":
        return default
    want = normalize_address(requested)
    for addr in account:
        if normalize_address(addr) == want:
            return addr
    raise Refused(f"{requested!r} is not one of this account's addresses: {', '.join(account)}")


def _clean_subject(subject: str) -> str:
    subject = re.sub(r"[\r\n\t]+", " ", subject or "").strip()
    return subject[:MAX_SUBJECT]


def _check_body(body: str) -> str:
    if len(body) > MAX_BODY:
        raise InvalidArgument(f"body is longer than {MAX_BODY} characters")
    return body.replace("\r\n", "\n").replace("\r", "\n")


def _h(addrs: list[Address]) -> list[HAddress]:
    out = []
    for a in addrs:
        try:
            out.append(HAddress(display_name=a.name, addr_spec=a.address))
        except (ValueError, IndexError) as exc:
            raise InvalidArgument(f"{a.address!r} is not an address") from exc
    return out


def message(
    sender: str,
    to: list[Address],
    cc: list[Address],
    bcc: list[Address],
    subject: str,
    body: str,
    now: datetime | None = None,
    sender_name: str = "",
) -> EmailMessage:
    if len(to) + len(cc) + len(bcc) > MAX_RECIPIENTS:
        raise InvalidArgument(f"at most {MAX_RECIPIENTS} recipients")
    msg = EmailMessage(policy=email.policy.SMTP)
    msg["From"] = _h([Address(sender_name, sender)])
    if to:
        msg["To"] = _h(to)
    if cc:
        msg["Cc"] = _h(cc)
    if bcc:
        msg["Bcc"] = _h(bcc)
    msg["Subject"] = _clean_subject(subject)
    msg["Date"] = email.utils.format_datetime(now or datetime.now(UTC))
    msg["Message-ID"] = email.utils.make_msgid(domain=sender.rpartition("@")[2])
    msg["MIME-Version"] = "1.0"
    msg.set_content(_check_body(body), subtype="plain", charset="utf-8", cte="quoted-printable")
    return msg


def to_bytes(msg: EmailMessage) -> bytes:
    return msg.as_bytes(policy=email.policy.SMTP)


# ── replies and forwards ─────────────────────────────────────────────────


_RE = re.compile(r"^\s*(re|aw|sv|antw|r)\s*(\[\d+\])?\s*:", re.I)
_FWD = re.compile(r"^\s*(fwd?|wg|tr|rv|enc)\s*(\[\d+\])?\s*:", re.I)


def reply_subject(subject: str) -> str:
    subject = _clean_subject(subject)
    return subject if _RE.match(subject) else f"Re: {subject}".strip()


def forward_subject(subject: str) -> str:
    subject = _clean_subject(subject)
    return subject if _FWD.match(subject) else f"Fwd: {subject}".strip()


def thread_headers(orig: Headers) -> tuple[str | None, str | None]:
    """In-Reply-To and References for a reply: the original's references
    (without Bridge's self-appended <id@protonmail.internalid>) plus its
    Message-ID, the newest MAX_REFERENCES kept."""
    own_ids = message_ids(orig.get("Message-ID"))
    if not own_ids:
        return None, None
    msgid = own_ids[0]
    refs = [r for r in message_ids(orig.get("References")) if not INTERNAL_REF.search(r) and r != msgid]
    if not refs:
        refs = [r for r in message_ids(orig.get("In-Reply-To")) if not INTERNAL_REF.search(r)]
    chain = (refs + [msgid])[-MAX_REFERENCES:]
    return f"<{msgid}>", " ".join(f"<{r}>" for r in chain)


def reply_recipients(orig: Headers, own: tuple[str, ...], reply_all: bool) -> tuple[list[Address], list[Address]]:
    mine = {normalize_address(a) for a in own}
    to = orig.addresses("Reply-To") or orig.addresses("From")
    if to and all(normalize_address(a.address) in mine for a in to):
        # Replying to one's own message: it goes to the people it went to.
        to = orig.addresses("To")
    to = dedupe(to, mine)
    cc: list[Address] = []
    if reply_all:
        taken = mine | {normalize_address(a.address) for a in to}
        cc = dedupe(orig.addresses("To", "Cc"), taken)
    return to, cc


def quoted(orig: Headers, text: str) -> str:
    who = ", ".join(a.formatted() for a in orig.addresses("From")) or "someone"
    when = orig.get("Date") or "an earlier date"
    lines = text[:MAX_QUOTE].splitlines() or [""]
    return f"On {when}, {who} wrote:\n" + "\n".join("> " + line if line else ">" for line in lines)


def forwarded_block(orig: Headers, text: str) -> str:
    rows = [
        "---------- Forwarded message ----------",
        "From: " + ", ".join(a.formatted() for a in orig.addresses("From")),
        "Date: " + (orig.get("Date") or ""),
        "Subject: " + (orig.get("Subject") or ""),
        "To: " + ", ".join(a.formatted() for a in orig.addresses("To")),
    ]
    cc = orig.addresses("Cc")
    if cc:
        rows.append("Cc: " + ", ".join(a.formatted() for a in cc))
    return "\n".join(rows) + "\n\n" + text[:MAX_BODY]


@dataclass
class FileAttachment:
    filename: str
    content_type: str
    data: bytes


def attach(msg: EmailMessage, files: list[FileAttachment]) -> None:
    for f in files:
        maintype, _, subtype = f.content_type.partition("/")
        if not subtype or not re.fullmatch(r"[a-z0-9.+\-]+", maintype + subtype):
            maintype, subtype = "application", "octet-stream"
        if maintype == "multipart":
            maintype, subtype = "application", "octet-stream"
        name = re.sub(r"[\r\n\x00/\\]", "_", f.filename or "attachment")[:200]
        msg.add_attachment(f.data, maintype=maintype, subtype=subtype, filename=name)


def invite_reply_message(
    sender: str,
    sender_name: str,
    organizer: str,
    organizer_name: str,
    subject: str,
    body: str,
    ics: bytes,
    now: datetime | None = None,
) -> EmailMessage:
    msg = message(sender, [Address(organizer_name, organizer)], [], [], subject, body, now=now, sender_name=sender_name)
    msg.add_attachment(
        ics,
        maintype="text",
        subtype="calendar",
        filename="invite.ics",
        params={"method": "REPLY", "charset": "utf-8"},
    )
    return msg
