"""The IMAP command guard.

Every byte the server writes to Bridge's IMAP socket passes through
`WireGuard.feed` (hooked into the socket writer itself, see imapconn.py):
it reassembles each command line, checks it with `CommandGuard`, and only
then releases it. That sits below imaplib and below imapclient, whose
search/move write to the socket directly, so no library path skips it.
Each tool runs under a `Policy` naming the writes it needs; everything
outside the read set plus that policy raises GuardViolation.

The read set is: CAPABILITY, NOOP, LOGOUT, LOGIN, STARTTLS, LIST, STATUS,
EXAMINE, UNSELECT, UID SEARCH, and UID FETCH whose body sections are all
BODY.PEEK[...] (a non-PEEK fetch sets \\Seen). SELECT, STORE, COPY, MOVE,
EXPUNGE, APPEND, CREATE, RENAME and DELETE exist only inside a policy that
names them, with their mailbox and flag arguments checked. CLOSE (which
expunges) and plain EXPUNGE are never allowed."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from imapclient import imap_utf7

from .errors import GuardViolation

MailboxPred = Callable[[str], bool]

MAX_WRITE_UIDS = 50
MAX_APPEND_BYTES = 30 * 1024 * 1024

_CTL = re.compile(r"[\x00\r\n]")
_ATOM = re.compile(r"[^\s(){%*\"\\\]\x00-\x1f\x7f]+")
_UIDSET = re.compile(r"(?:\d+(?::\d+)?)(?:,\d+(?::\d+)?)*")
_UIDSET_READ = re.compile(r"(?:(?:\d+|\*)(?::(?:\d+|\*))?)(?:,(?:\d+|\*)(?::(?:\d+|\*))?)*")
_DATE = re.compile(r"\d{1,2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{4}", re.I)
_FIELD = re.compile(r"[A-Za-z0-9_\-]+")
_STORE_OPS = frozenset({"+FLAGS", "-FLAGS", "+FLAGS.SILENT", "-FLAGS.SILENT"})
_STATUS_ITEMS = frozenset({"MESSAGES", "RECENT", "UIDNEXT", "UIDVALIDITY", "UNSEEN"})
_PLAIN_FETCH = frozenset({"UID", "FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODYSTRUCTURE"})


@dataclass(frozen=True)
class Policy:
    """The writes one tool may perform. Reads are always allowed."""

    name: str
    select: MailboxPred | None = None
    store: Callable[[str, str, frozenset[str]], bool] | None = None  # (selected, op, flags)
    copy_to: MailboxPred | None = None
    move_to: MailboxPred | None = None
    expunge_in: MailboxPred | None = None
    append: Callable[[str, frozenset[str]], bool] | None = None
    create: MailboxPred | None = None
    rename: Callable[[str, str], bool] | None = None
    delete: MailboxPred | None = None

    @property
    def read_only(self) -> bool:
        return not any(
            (self.select, self.store, self.copy_to, self.move_to, self.expunge_in, self.append)
            + (self.create, self.rename, self.delete)
        )


READ = Policy("read")


def _deny(policy: Policy, what: str) -> GuardViolation:
    return GuardViolation(f"IMAP command refused by the {policy.name} policy: {what}")


def _astring(arg: str) -> str:
    if len(arg) >= 2 and arg[0] == '"' and arg[-1] == '"':
        body = arg[1:-1]
        out = []
        i = 0
        while i < len(body):
            c = body[i]
            if c == "\\":
                if i + 1 >= len(body) or body[i + 1] not in '"\\':
                    raise ValueError("bad escape")
                out.append(body[i + 1])
                i += 2
                continue
            if c == '"':
                raise ValueError("bare quote")
            out.append(c)
            i += 1
        return "".join(out)
    if _ATOM.fullmatch(arg):
        return arg
    raise ValueError("not an astring")


def _mailbox(arg: str) -> str:
    return imap_utf7.decode(_astring(arg).encode("ascii"))


def _flag_list(arg: str) -> frozenset[str]:
    if not (arg.startswith("(") and arg.endswith(")")):
        raise ValueError("not a flag list")
    words = arg[1:-1].split()
    for w in words:
        if not re.fullmatch(r"\\?[A-Za-z$][A-Za-z0-9$_\-]*", w):
            raise ValueError("bad flag")
    return frozenset("\\" + w[1:].capitalize() if w.startswith("\\") else w for w in words)


def _count(uidset: str) -> int:
    n = 0
    for item in uidset.split(","):
        if ":" in item:
            a, b = item.split(":")
            n += abs(int(b) - int(a)) + 1
        else:
            n += 1
    return n


def _section_ok(section: str) -> bool:
    """RFC 3501 section-spec: [part] [HEADER | HEADER.FIELDS[.NOT] (f..) | TEXT | MIME]."""
    m = re.fullmatch(r"((?:\d+)(?:\.\d+)*)?(?:(?(1)\.)(.+))?", section)
    if not m:
        return False
    part, text = m.group(1), m.group(2)
    if text is None:
        return True
    text_u = text.upper()
    if text_u in ("HEADER", "TEXT"):
        return True
    if text_u == "MIME":
        return part is not None
    fm = re.fullmatch(r"HEADER\.FIELDS(?:\.NOT)? \(([^()]*)\)", text, re.I)
    return bool(fm) and all(_FIELD.fullmatch(f) for f in fm.group(1).split()) and bool(fm.group(1).split())


_FETCH_ITEM = re.compile(r"BODY\.PEEK\[([^\]]*)\](?:<\d+\.\d+>)?|[A-Za-z0-9.]+", re.I)


def _fetch_items_ok(arg: str) -> bool:
    inner = arg[1:-1] if arg.startswith("(") and arg.endswith(")") else arg
    pos = 0
    seen = False
    while pos < len(inner):
        if inner[pos] == " ":
            pos += 1
            continue
        m = _FETCH_ITEM.match(inner, pos)
        if not m:
            return False
        item = m.group(0)
        if m.group(1) is not None:
            if not _section_ok(m.group(1)):
                return False
        elif item.upper() not in _PLAIN_FETCH:
            return False
        pos = m.end()
        if pos < len(inner) and inner[pos] != " ":
            return False
        seen = True
    return seen


# ── SEARCH ───────────────────────────────────────────────────────────────

_SEARCH_NOARG = frozenset(
    "ALL ANSWERED DELETED DRAFT FLAGGED NEW OLD RECENT SEEN UNANSWERED UNDELETED UNDRAFT UNFLAGGED UNSEEN".split()
)
_SEARCH_DATE = frozenset("BEFORE ON SINCE SENTBEFORE SENTON SENTSINCE".split())
_SEARCH_STRING = frozenset("BCC BODY CC FROM SUBJECT TEXT TO".split())


def _search_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == " ":
            i += 1
        elif c in "()":
            tokens.append(c)
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ValueError("unterminated string")
            tokens.append(text[i : j + 1])
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in ' ()"':
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def _search_key(tokens: list[str], pos: int, depth: int = 0) -> int:
    if depth > 32 or pos >= len(tokens):
        raise ValueError("bad search")
    tok = tokens[pos]
    key = tok.upper()
    if tok == "(":
        pos += 1
        while pos < len(tokens) and tokens[pos] != ")":
            pos = _search_key(tokens, pos, depth + 1)
        if pos >= len(tokens):
            raise ValueError("unbalanced search")
        return pos + 1
    if key in _SEARCH_NOARG:
        return pos + 1
    if key in _SEARCH_DATE:
        if pos + 1 >= len(tokens) or not _DATE.fullmatch(tokens[pos + 1]):
            raise ValueError("bad date")
        return pos + 2
    if key in _SEARCH_STRING:
        _astring(tokens[pos + 1])
        return pos + 2
    if key == "HEADER":
        if not _FIELD.fullmatch(_astring(tokens[pos + 1])):
            raise ValueError("bad header field")
        _astring(tokens[pos + 2])
        return pos + 3
    if key in ("LARGER", "SMALLER"):
        if not tokens[pos + 1].isdigit():
            raise ValueError("bad size")
        return pos + 2
    if key == "UID":
        if not _UIDSET_READ.fullmatch(tokens[pos + 1]):
            raise ValueError("bad uid set")
        return pos + 2
    if key == "NOT":
        return _search_key(tokens, pos + 1, depth + 1)
    if key == "OR":
        return _search_key(tokens, _search_key(tokens, pos + 1, depth + 1), depth + 1)
    raise ValueError(f"search key {key!r}")


def _search_ok(args: list[str]) -> bool:
    try:
        tokens = _search_tokens(" ".join(args))
        pos = 0
        if tokens[:1] and tokens[0].upper() == "CHARSET":
            if len(tokens) < 2 or tokens[1].upper() not in ("UTF-8", "US-ASCII"):
                return False
            pos = 2
        if pos >= len(tokens):
            return False
        while pos < len(tokens):
            pos = _search_key(tokens, pos)
        return True
    except (ValueError, IndexError):
        return False


# ── the guard ────────────────────────────────────────────────────────────


class CommandGuard:
    def __init__(self) -> None:
        self.policy: Policy = READ
        self.selected: str | None = None
        self.writable = False
        self.writes_sent = 0

    def reset(self, policy: Policy) -> None:
        self.policy = policy
        self.writes_sent = 0

    def check(self, name: str, args: Iterable[object], literal: object = None) -> None:
        """Raise GuardViolation unless the command is allowed now."""
        policy = self.policy
        name = name.upper()
        argv: list[str] = []
        for a in args:
            if a is None:
                continue
            s = a.decode("latin-1") if isinstance(a, bytes) else str(a)
            if _CTL.search(s):
                raise _deny(policy, "CR, LF or NUL in an argument")
            argv.append(s)
        try:
            self._check(policy, name, argv, literal)
        except (ValueError, IndexError) as exc:
            raise _deny(policy, f"{name}: malformed arguments ({exc})") from None

    def _check(self, p: Policy, name: str, argv: list[str], literal: object) -> None:
        if literal is not None and name != "APPEND":
            raise _deny(p, f"literal with {name}")
        if name in ("CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "UNSELECT"):
            if argv:
                raise _deny(p, f"{name} takes no arguments")
            if name == "UNSELECT":
                self.selected, self.writable = None, False
            return
        if name == "LOGIN":
            if len(argv) != 2:
                raise _deny(p, "LOGIN")
            return
        if name == "LIST":
            if len(argv) != 2 or _astring(argv[0]) != "":
                raise _deny(p, "LIST with a reference")
            _astring(argv[1])
            return
        if name == "STATUS":
            _mailbox(argv[0])
            items = argv[1].strip("()").split()
            if len(argv) != 2 or not items or not set(i.upper() for i in items) <= _STATUS_ITEMS:
                raise _deny(p, "STATUS items")
            return
        if name == "EXAMINE":
            if len(argv) != 1:
                raise _deny(p, "EXAMINE")
            self.selected, self.writable = _mailbox(argv[0]), False
            return
        if name == "SELECT":
            box = _mailbox(argv[0]) if len(argv) == 1 else None
            if box is None or p.select is None or not p.select(box):
                raise _deny(p, f"SELECT {box!r}")
            self.selected, self.writable = box, True
            return
        if name == "UID":
            return self._check_uid(p, argv)
        if name == "APPEND":
            size = len(literal) if isinstance(literal, (bytes, bytearray)) else literal
            if p.append is None or not isinstance(size, int):
                raise _deny(p, "APPEND")
            if size > MAX_APPEND_BYTES:
                raise _deny(p, "APPEND larger than the cap")
            box = _mailbox(argv[0])
            flags = _flag_list(argv[1]) if len(argv) > 1 and argv[1].startswith("(") else frozenset()
            if not p.append(box, flags):
                raise _deny(p, f"APPEND to {box!r} with {sorted(flags)}")
            self.writes_sent += 1
            return
        if name in ("CREATE", "DELETE"):
            box = _mailbox(argv[0]) if len(argv) == 1 else ""
            pred = p.create if name == "CREATE" else p.delete
            if pred is None or not pred(box):
                raise _deny(p, f"{name} {box!r}")
            self.writes_sent += 1
            return
        if name == "RENAME":
            if len(argv) != 2 or p.rename is None or not p.rename(_mailbox(argv[0]), _mailbox(argv[1])):
                raise _deny(p, "RENAME")
            self.writes_sent += 1
            return
        raise _deny(p, name)

    def _check_uid(self, p: Policy, argv: list[str]) -> None:
        if not argv:
            raise _deny(p, "UID")
        sub, rest = argv[0].upper(), argv[1:]
        if sub == "SEARCH":
            if self.selected is None or not _search_ok(rest):
                raise _deny(p, "UID SEARCH")
            return
        if sub == "FETCH":
            if self.selected is None or len(rest) != 2 or not _UIDSET_READ.fullmatch(rest[0]):
                raise _deny(p, "UID FETCH")
            if not _fetch_items_ok(rest[1]):
                raise _deny(p, f"UID FETCH items {rest[1]!r}")
            return
        # Writes: an explicit, bounded UID set in a mailbox opened by SELECT.
        if not rest or not _UIDSET.fullmatch(rest[0]) or _count(rest[0]) > MAX_WRITE_UIDS:
            raise _deny(p, f"UID {sub} needs an explicit set of at most {MAX_WRITE_UIDS} UIDs")
        if self.selected is None or not self.writable:
            raise _deny(p, f"UID {sub} outside a SELECTed mailbox")
        if sub == "STORE":
            if len(rest) != 3 or rest[1].upper() not in _STORE_OPS or p.store is None:
                raise _deny(p, "UID STORE")
            flags = _flag_list(rest[2])
            if not flags or not p.store(self.selected, rest[1].upper(), flags):
                raise _deny(p, f"UID STORE {rest[1]} {sorted(flags)} in {self.selected!r}")
        elif sub in ("COPY", "MOVE"):
            pred = p.copy_to if sub == "COPY" else p.move_to
            if len(rest) != 2 or pred is None or not pred(_mailbox(rest[1])):
                raise _deny(p, f"UID {sub}")
        elif sub == "EXPUNGE":
            if len(rest) != 1 or p.expunge_in is None or not p.expunge_in(self.selected):
                raise _deny(p, f"UID EXPUNGE in {self.selected!r}")
        else:
            raise _deny(p, f"UID {sub}")
        self.writes_sent += 1


# ── on the wire ──────────────────────────────────────────────────────────

_LITERAL_END = re.compile(rb"\{(\d+)(\+?)\}\r\n$")


def split_args(text: str) -> list[str]:
    """Top-level arguments of a command line: quoted strings, parenthesized
    lists and bracketed sections stay whole."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == " ":
            i += 1
            continue
        start, depth, bracket = i, 0, 0
        while i < n:
            c = text[i]
            if c == '"':
                i += 1
                while i < n and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
                if i >= n:
                    raise ValueError("unterminated string")
            elif c == "[":
                bracket += 1
            elif c == "]":
                bracket -= 1
            elif c == "(" and not bracket:
                depth += 1
            elif c == ")" and not bracket:
                depth -= 1
                if depth < 0:
                    raise ValueError("unbalanced parentheses")
            elif c == " " and depth == 0 and bracket == 0:
                break
            i += 1
        if depth or bracket:
            raise ValueError("unbalanced command")
        out.append(text[start:i])
    return out


class WireGuard:
    """Sits between the IMAP client and the socket. Outgoing bytes are held
    until a command line is complete, checked, then released; a literal's
    bytes pass only after the line announcing it was allowed, and nothing
    but CRLF may follow a literal. A refused command never reaches the
    socket; the connection is then unusable and must be dropped."""

    def __init__(self, guard: CommandGuard) -> None:
        self.guard = guard
        self._line = bytearray()
        self._literal_left = 0
        self._after_literal = False

    def feed(self, data: bytes) -> list[bytes]:
        out: list[bytes] = []
        view = memoryview(bytes(data))
        i = 0
        while i < len(view):
            if self._literal_left:
                chunk = bytes(view[i : i + self._literal_left])
                out.append(chunk)
                self._literal_left -= len(chunk)
                i += len(chunk)
                self._after_literal = self._literal_left == 0
                continue
            end = bytes(view[i:]).find(b"\n")
            if end < 0:
                self._line += view[i:]
                if len(self._line) > 1 << 20:
                    raise _deny(self.guard.policy, "command line too long")
                break
            self._line += view[i : i + end + 1]
            i += end + 1
            line, self._line = bytes(self._line), bytearray()
            if not line.endswith(b"\r\n") or b"\r" in line[:-2] or b"\n" in line[:-2] or b"\x00" in line:
                raise _deny(self.guard.policy, "malformed command line")
            if self._after_literal:
                self._after_literal = False
                if line != b"\r\n":
                    raise _deny(self.guard.policy, "data after a literal")
                out.append(line)
                continue
            m = _LITERAL_END.search(line)
            body = line[: m.start()] if m else line[:-2]
            self._check(body.decode("latin-1").rstrip(" "), int(m.group(1)) if m else None)
            out.append(line)
            if m:
                self._literal_left = int(m.group(1))
                self._after_literal = self._literal_left == 0
        return out

    def _check(self, text: str, literal: int | None) -> None:
        parts = text.split(" ", 2)
        if len(parts) < 2 or not _ATOM.fullmatch(parts[0]):
            raise _deny(self.guard.policy, "malformed command line")
        name = parts[1].upper()
        try:
            args = split_args(parts[2]) if len(parts) > 2 else []
        except ValueError as exc:
            raise _deny(self.guard.policy, f"{name}: {exc}") from None
        self.guard.check(name, args, literal)
