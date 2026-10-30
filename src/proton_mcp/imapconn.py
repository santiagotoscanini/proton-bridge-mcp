"""IMAP sessions to Bridge: imapclient on top, the guard underneath.

imapclient speaks the protocol and parses responses; it drives imaplib,
whose socket writer (`send`) is the one place every byte leaves through —
imapclient's own search/move write there directly. The `WireGuard` sits in
that writer. `Imap` turns imapclient's results into plain values and every
failure into a typed error; `Bridge` owns credentials and a small pool and
retries a read once on a fresh connection when Bridge dropped the old one
(it closes sockets without BYE while Proton's API is unreachable)."""

from __future__ import annotations

import imaplib
import logging
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientAbortError, IMAPClientError, LoginError
from imapclient.imap4 import IMAP4WithTimeout
from imapclient.util import to_unicode

from .credentials import Credentials, Source, ssl_context
from .errors import AuthFailed, BridgeUnavailable, GuardViolation, ImapError, MailError
from .guard import READ, CommandGuard, Policy, WireGuard
from .uidplus import UidCode, find_code

log = logging.getLogger("proton_mcp.imap")
# imapclient logs commands and responses (mail content) at DEBUG; never emit them.
logging.getLogger("imapclient").setLevel(logging.WARNING)
T = TypeVar("T")

CONNECT_TIMEOUT = 10.0
OP_TIMEOUT = 30.0
FETCH_CHUNK = 200


class ConnectionLost(Exception):
    """The connection is unusable; `writes_sent` says whether a write was on the wire."""

    def __init__(self, message: str, writes_sent: int = 0) -> None:
        super().__init__(message)
        self.writes_sent = writes_sent


class ResponseTooLarge(MailError):
    """A response line exceeded imaplib's limit; the caller narrows and retries."""

    kind = "response_too_large"


class _Wired:
    """imaplib's socket writer, with the guard in front of it."""

    wire: WireGuard

    def send(self, data: bytes) -> None:
        for chunk in self.wire.feed(data):
            super().send(chunk)  # type: ignore[misc]


class _ImplicitTLS(_Wired, imaplib.IMAP4):
    def __init__(self, host: str, port: int, ctx: ssl.SSLContext, tls_name: str, timeout: float, wire: WireGuard):
        self.wire, self._ctx, self._tls_name, self._timeout = wire, ctx, tls_name, timeout
        super().__init__(host, port)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=self._timeout)
        return self._ctx.wrap_socket(sock, server_hostname=self._tls_name)


class _Plain(_Wired, IMAP4WithTimeout):
    def __init__(self, host: str, port: int, timeout: float, wire: WireGuard):
        self.wire = wire
        super().__init__(host, port, timeout)


class Client(IMAPClient):
    """imapclient over a guarded, pinned connection; STARTTLS is mandatory
    when the listener is not implicit TLS."""

    def __init__(self, creds: Credentials, guard: CommandGuard, timeout: float = CONNECT_TIMEOUT) -> None:
        self._creds = creds
        self._ctx = ssl_context(creds.cert_pem)
        self._wire = WireGuard(guard)
        super().__init__(creds.imap.host, port=creds.imap.port, use_uid=True, ssl=creds.imap.implicit_tls, timeout=timeout)
        self.normalise_times = False
        if not creds.imap.implicit_tls:
            if not self.has_capability("STARTTLS"):
                self.shutdown()
                raise ssl.SSLError("server does not offer STARTTLS")
            self.starttls(self._ctx)

    def _create_IMAP4(self) -> imaplib.IMAP4:  # noqa: N802 - imapclient's hook
        ep, timeout = self._creds.imap, self._timeout.connect
        if ep.implicit_tls:
            return _ImplicitTLS(ep.host, ep.port, self._ctx, self._creds.tls_name, timeout, self._wire)
        return _Plain(ep.host, ep.port, timeout, self._wire)

    def starttls(self, ssl_context: ssl.SSLContext | None = None) -> bytes:
        # imapclient's own checks the certificate against the connect host;
        # Bridge's names only 127.0.0.1, so the pinned name is used instead.
        typ, data = self._imap._simple_command("STARTTLS")
        self._checkok("starttls", typ, data)
        self._starttls_done = True
        self._imap.sock = self._ctx.wrap_socket(self._imap.sock, server_hostname=self._creds.tls_name)
        self._imap.file = self._imap.sock.makefile("rb")
        self._cached_capabilities = None
        return data[0]


@dataclass(frozen=True)
class MailboxState:
    name: str
    uidvalidity: int
    exists: int


@dataclass(frozen=True)
class EnvAddress:
    name: str  # raw, possibly RFC 2047 encoded
    address: str


@dataclass(frozen=True)
class Envelope:
    subject: str  # raw, possibly RFC 2047 encoded
    from_: tuple[EnvAddress, ...]
    to: tuple[EnvAddress, ...]
    cc: tuple[EnvAddress, ...]
    bcc: tuple[EnvAddress, ...]
    in_reply_to: str
    message_id: str


@dataclass
class Entry:
    """One message's FETCH results, as plain values."""

    uid: int
    flags: list[str] = field(default_factory=list)
    date: int | None = None  # INTERNALDATE, epoch seconds
    size: int | None = None
    envelope: Envelope | None = None
    bodystructure: Any = None  # imapclient's BodyData
    sections: dict[str, bytes] = field(default_factory=dict)  # "BODY[1]<0>" -> bytes

    def section(self, prefix: str) -> bytes | None:
        prefix = prefix.upper()
        for key, value in self.sections.items():
            if key.startswith(prefix):
                return value
        return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1")
    return str(value)


def _addresses(items: Any) -> tuple[EnvAddress, ...]:
    out = []
    for a in items or ():
        if a.host is None:  # group syntax markers
            continue
        address = f"{_text(a.mailbox)}@{_text(a.host)}" if a.mailbox else ""
        out.append(EnvAddress(_text(a.name), address))
    return tuple(out)


def _envelope(env: Any) -> Envelope | None:
    if env is None:
        return None
    return Envelope(
        subject=_text(env.subject),
        from_=_addresses(env.from_),
        to=_addresses(env.to),
        cc=_addresses(env.cc),
        bcc=_addresses(env.bcc),
        in_reply_to=_text(env.in_reply_to),
        message_id=_text(env.message_id),
    )


def _entry(uid: int, data: dict[bytes, Any]) -> Entry:
    e = Entry(uid)
    for raw_key, value in data.items():
        key = to_unicode(raw_key).upper()
        if key == "FLAGS":
            e.flags = [to_unicode(f) for f in value]
        elif key == "INTERNALDATE" and isinstance(value, datetime):
            e.date = int(value.timestamp())
        elif key == "RFC822.SIZE":
            e.size = int(value)
        elif key == "ENVELOPE":
            e.envelope = _envelope(value)
        elif key == "BODYSTRUCTURE":
            e.bodystructure = value
        elif key.startswith("BODY["):
            e.sections[key] = value if isinstance(value, bytes) else b"" if value is None else _text(value).encode()
    return e


def _reason(exc: BaseException) -> str:
    text = re.sub(r"^\w+ failed: ", "", str(exc)).strip()
    return text[:200] or "no reason given"


class Imap:
    """One authenticated connection. Not thread-safe; the pool hands it to
    one tool at a time."""

    def __init__(self, client: Client, guard: CommandGuard) -> None:
        self.client = client
        self.guard = guard
        self.alive = True
        self.last_used = time.monotonic()

    @classmethod
    def connect(cls, creds: Credentials, timeout: float = CONNECT_TIMEOUT) -> Imap:
        guard = CommandGuard()
        try:
            client = Client(creds, guard, timeout)
        except ssl.SSLCertVerificationError as exc:
            raise BridgeUnavailable(f"Bridge's certificate does not match the pinned one: {exc.verify_message}") from exc
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError) as exc:
            raise ConnectionLost("Bridge closed the connection during the TLS handshake") from exc
        except ssl.SSLError as exc:
            raise BridgeUnavailable(f"TLS with Bridge's IMAP listener failed: {exc}") from exc
        except ConnectionRefusedError as exc:
            raise ConnectionLost("Bridge's IMAP listener refuses connections") from exc
        except (OSError, imaplib.IMAP4.error, EOFError) as exc:
            raise ConnectionLost(f"cannot reach Bridge's IMAP listener: {type(exc).__name__}") from exc
        session = cls(client, guard)
        try:
            client.login(creds.login, creds.password)
        except LoginError as exc:
            session.close()
            raise AuthFailed("Bridge refused the login") from exc
        except (imaplib.IMAP4.abort, OSError, EOFError) as exc:
            session.close()
            raise ConnectionLost(f"connection failed during login: {type(exc).__name__}") from exc
        except imaplib.IMAP4.error as exc:
            session.close()
            raise AuthFailed("Bridge refused the login") from exc
        client.socket().settimeout(OP_TIMEOUT)
        return session

    # ── plumbing ─────────────────────────────────────────────────────────

    def _call(self, what: str, fn: Callable[[], T], timeout: float | None = None) -> T:
        if not self.alive:
            raise ConnectionLost("connection already closed", self.guard.writes_sent)
        if timeout is not None:
            self.client.socket().settimeout(timeout)
        try:
            return fn()
        except GuardViolation:
            self.close()  # the client's view of the protocol is no longer the server's
            raise
        except (imaplib.IMAP4.abort, IMAPClientAbortError, OSError, EOFError) as exc:
            self.close()
            raise ConnectionLost(f"{what}: Bridge dropped the connection ({type(exc).__name__})", self.guard.writes_sent) from exc
        except (IMAPClientError, imaplib.IMAP4.error) as exc:
            if "got more than" in str(exc):
                self.close()
                raise ResponseTooLarge(f"{what}: the response was too large") from exc
            raise ImapError(f"{what}: Bridge refused it ({_reason(exc)})") from exc
        finally:
            self.last_used = time.monotonic()
            if timeout is not None and self.alive:
                self.client.socket().settimeout(OP_TIMEOUT)

    def close(self) -> None:
        self.alive = False
        try:
            self.client.shutdown()
        except Exception:  # noqa: BLE001 - closing a dead socket
            pass

    def logout(self) -> None:
        if self.alive:
            try:
                self.client.logout()
            except Exception:  # noqa: BLE001
                pass
        self.close()

    def _untagged(self, name: str) -> list[Any]:
        return self.client._imap.untagged_responses.pop(name, [])

    # ── reads ────────────────────────────────────────────────────────────

    def noop(self) -> None:
        self._call("NOOP", self.client.noop)

    def list(self) -> list[tuple[tuple[str, ...], str]]:
        """(attributes, name) of every mailbox, names decoded."""
        rows = self._call("LIST", lambda: self.client.list_folders("", "*"))
        return [(tuple(to_unicode(f) for f in flags), to_unicode(name)) for flags, _delim, name in rows]

    def status(self, mailbox: str) -> dict[str, int]:
        res = self._call("STATUS", lambda: self.client.folder_status(mailbox, ["MESSAGES", "UNSEEN", "UIDVALIDITY", "UIDNEXT"]))
        return {to_unicode(k).upper(): int(v) for k, v in res.items()}

    def _open(self, mailbox: str, readonly: bool) -> MailboxState:
        res = self._call(
            ("EXAMINE " if readonly else "SELECT ") + mailbox, lambda: self.client.select_folder(mailbox, readonly=readonly)
        )
        return MailboxState(mailbox, int(res.get(b"UIDVALIDITY", 0)), int(res.get(b"EXISTS", 0)))

    def examine(self, mailbox: str) -> MailboxState:
        return self._open(mailbox, readonly=True)

    def select(self, mailbox: str) -> MailboxState:
        return self._open(mailbox, readonly=False)

    def unselect(self) -> None:
        self._call("UNSELECT", self.client.unselect_folder)

    def search(self, criteria: list[Any], timeout: float | None = None) -> list[int]:
        return [int(u) for u in self._call("UID SEARCH", lambda: self.client.search(criteria), timeout)]

    def fetch(self, uids: list[int], items: list[str], timeout: float | None = None) -> list[Entry]:
        """UID FETCH in chunks. Missing UIDs are simply absent."""
        out: list[Entry] = []
        ordered = sorted(set(uids))
        for i in range(0, len(ordered), FETCH_CHUNK):
            chunk = ordered[i : i + FETCH_CHUNK]
            res = self._call("UID FETCH", lambda c=chunk: self.client.fetch(c, items), timeout)
            wanted = set(chunk)
            for uid, data in res.items():
                if uid in wanted:
                    out.append(_entry(uid, data))
        return out

    # ── writes (each must be allowed by the session's policy) ────────────

    def store(self, uids: list[int], add: bool, flags: list[str], silent: bool = False) -> dict[int, list[str]]:
        op = self.client.add_flags if add else self.client.remove_flags
        res = self._call("UID STORE", lambda: op(uids, flags, silent=silent))
        return {int(u): [to_unicode(f) for f in fl] for u, fl in (res or {}).items()}

    def copy(self, uids: list[int], dest: str) -> UidCode | None:
        self._untagged("COPYUID")
        res = self._call("UID COPY", lambda: self.client.copy(uids, dest))
        return find_code("COPYUID", self._untagged("COPYUID"), [res])

    def move(self, uids: list[int], dest: str) -> UidCode | None:
        self._untagged("COPYUID")
        res = self._call("UID MOVE", lambda: self.client.move(uids, dest))
        return find_code("COPYUID", self._untagged("COPYUID"), [res])

    def expunge(self, uids: list[int]) -> None:
        self._call("UID EXPUNGE", lambda: self.client.uid_expunge(uids))

    def append(self, mailbox: str, flags: list[str], message: bytes) -> UidCode | None:
        self._untagged("APPENDUID")
        res = self._call("APPEND", lambda: self.client.append(mailbox, message, flags=flags), timeout=120.0)
        return find_code("APPENDUID", self._untagged("APPENDUID"), [res])

    def create(self, mailbox: str) -> None:
        self._call("CREATE", lambda: self.client.create_folder(mailbox))

    def rename(self, old: str, new: str) -> None:
        self._call("RENAME", lambda: self.client.rename_folder(old, new))

    def delete(self, mailbox: str) -> None:
        self._call("DELETE", lambda: self.client.delete_folder(mailbox))


class Bridge:
    """Credentials plus a small pool of authenticated connections."""

    def __init__(
        self,
        source: Source,
        max_connections: int = 3,
        idle_check_after: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.source = source
        self._creds: Credentials | None = None
        self._creds_lock = threading.Lock()
        self._idle: list[Imap] = []
        self._idle_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_connections)
        self._idle_check_after = idle_check_after
        self._sleep = sleep

    def credentials(self, refresh: bool = False) -> Credentials:
        with self._creds_lock:
            if refresh or self._creds is None:
                self._creds = self.source.load()
            return self._creds

    def forget_credentials(self) -> None:
        with self._creds_lock:
            self._creds = None

    def _connect(self) -> Imap:
        try:
            return Imap.connect(self.credentials())
        except AuthFailed:
            # A re-login in Bridge changes the password: fetch it again once.
            return Imap.connect(self.credentials(refresh=True))

    @contextmanager
    def session(self, policy: Policy) -> Iterator[Imap]:
        if not self._slots.acquire(timeout=60):
            raise BridgeUnavailable("every Bridge connection is busy; try again")
        conn: Imap | None = None
        try:
            with self._idle_lock:
                conn = self._idle.pop() if self._idle else None
            if conn is not None and time.monotonic() - conn.last_used > self._idle_check_after:
                conn.guard.reset(READ)
                try:
                    conn.noop()
                except (ConnectionLost, MailError):
                    conn.close()
                    conn = None
            if conn is None:
                conn = self._connect()
            conn.guard.reset(policy)
            yield conn
        finally:
            if conn is not None:
                self._release(conn)
            self._slots.release()

    def _release(self, conn: Imap) -> None:
        if not conn.alive:
            return
        conn.guard.reset(READ)
        if conn.guard.writable:
            try:
                conn.unselect()
                conn.guard.selected, conn.guard.writable = None, False
            except (ConnectionLost, MailError):
                conn.close()
                return
        with self._idle_lock:
            self._idle.append(conn)

    def run(self, policy: Policy, fn: Callable[[Imap], T]) -> T:
        """Run fn on a session; on a dropped connection, retry once on a fresh
        one if no write had been sent."""
        for attempt in (0, 1):
            try:
                with self.session(policy) as imap:
                    return fn(imap)
            except ConnectionLost as exc:
                self.forget_credentials()
                if attempt == 0 and exc.writes_sent == 0:
                    log.info("retrying on a fresh connection: %s", exc)
                    self._sleep(0.3)
                    continue
                detail: dict[str, Any] = {"outcome": "unknown"} if exc.writes_sent else {}
                raise BridgeUnavailable(f"Bridge is unavailable: {exc}", **detail) from exc
        raise AssertionError("unreachable")

    def close(self) -> None:
        with self._idle_lock:
            idle, self._idle = self._idle, []
        for conn in idle:
            conn.logout()
