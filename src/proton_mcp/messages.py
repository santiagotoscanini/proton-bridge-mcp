"""Message-level reads shared by the tools: summaries from cheap FETCH items,
id resolution with the UIDVALIDITY check, and an INTERNALDATE cache.

On gluon (Bridge's IMAP engine), FLAGS, INTERNALDATE, RFC822.SIZE,
ENVELOPE and BODYSTRUCTURE come from its database; any BODY section (and
any SEARCH on a header or text) loads and decrypts the whole message. So
everything that can be decided from the database is decided before a body
is touched."""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime

from . import mime
from .errors import NotFound, StaleId
from .ids import MessageRef
from .imapconn import Entry, Envelope, Imap, MailboxState

SUMMARY_ITEMS = ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODYSTRUCTURE"]
INTERNAL_ID_ITEM = "BODY.PEEK[HEADER.FIELDS (X-PM-INTERNAL-ID)]"


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


_FLAG_WORDS = {
    "\\seen": "read",
    "\\flagged": "starred",
    "\\answered": "answered",
    "\\draft": "draft",
    "$forwarded": "forwarded",
    "forwarded": "forwarded",
}


def flag_words(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        word = _FLAG_WORDS.get(f.lower())
        if word and word not in out:
            out.append(word)
    return out


@dataclass
class Summary:
    mailbox: str
    uidvalidity: int
    uid: int
    flags: list[str]
    date: int
    size: int
    envelope: Envelope
    structure: mime.Part

    @property
    def key(self) -> tuple[str, int, int]:
        """Identical across the mailboxes one Proton message appears in."""
        return (self.envelope.message_id, self.date, self.size)

    def ref(self, internal_id: str) -> MessageRef:
        return MessageRef(self.mailbox, self.uidvalidity, self.uid, self.date, internal_id)

    @property
    def body(self) -> list[mime.Part]:
        return mime.body_parts(self.structure)

    @property
    def attachments(self) -> list[mime.Part]:
        return real_attachments(self.structure)


def real_attachments(root: mime.Part) -> list[mime.Part]:
    """Attachments a person would call attachments: not the body, not an
    inline image the body shows, not a PGP signature."""
    out = []
    for part in mime.attachments(root, mime.body_parts(root)):
        if part.content_type == "application/pgp-signature":
            continue
        if part.maintype == "image" and part.content_id and part.disposition != "attachment":
            continue
        out.append(part)
    return out


EMPTY_ENVELOPE = Envelope("", (), (), (), (), "", "")


def summaries(imap: Imap, state: MailboxState, uids: list[int]) -> list[Summary]:
    out = []
    for e in imap.fetch(uids, SUMMARY_ITEMS):
        try:
            structure = mime.from_bodystructure(e.bodystructure)
        except (ValueError, TypeError, IndexError):
            structure = mime.Part("application", "octet-stream")
        out.append(
            Summary(
                state.name, state.uidvalidity, e.uid, e.flags, e.date or 0, e.size or 0, e.envelope or EMPTY_ENVELOPE, structure
            )
        )
    return out


def internal_id(entry: Entry) -> str:
    raw = entry.section("BODY[HEADER.FIELDS") or b""
    return (mime.Headers.from_bytes(raw).get("X-Pm-Internal-Id") or "").strip()


def internal_ids(imap: Imap, uids: list[int]) -> dict[int, str]:
    return {e.uid: internal_id(e) for e in imap.fetch(uids, [INTERNAL_ID_ITEM])}


# ── the INTERNALDATE cache ───────────────────────────────────────────────


class DateCache:
    """UID → INTERNALDATE per (mailbox, UIDVALIDITY). Both are immutable
    under one UIDVALIDITY, so this never goes stale; it only holds numbers."""

    def __init__(self, max_entries: int = 1_000_000) -> None:
        self._maps: OrderedDict[tuple[str, int], dict[int, int]] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_entries

    def dates(self, imap: Imap, state: MailboxState, uids: list[int]) -> dict[int, int]:
        key = (state.name, state.uidvalidity)
        with self._lock:
            known = self._maps.setdefault(key, {})
            self._maps.move_to_end(key)
            missing = [u for u in uids if u not in known]
        fetched = (
            {e.uid: e.date for e in imap.fetch(missing, ["INTERNALDATE"], timeout=60.0) if e.date is not None} if missing else {}
        )
        with self._lock:
            known.update(fetched)
            total = sum(len(m) for m in self._maps.values())
            while total > self._max and len(self._maps) > 1:
                _, dropped = self._maps.popitem(last=False)
                total -= len(dropped)
            return {u: known[u] for u in uids if u in known}


# ── ids ──────────────────────────────────────────────────────────────────


def all_uids(imap: Imap, state: MailboxState, criteria: list[str] | None = None) -> list[int]:
    """UID SEARCH on flags only (database-only on gluon), split into UID
    ranges on very large mailboxes to stay under imaplib's line limit."""
    criteria = criteria or ["UNDELETED"]
    if state.exists <= 100_000:
        return imap.search(criteria)
    uidnext = imap.status(state.name).get("UIDNEXT", 0)
    imap.examine(state.name)
    out: list[int] = []
    for lo in range(1, max(uidnext, 2), 100_000):
        out.extend(imap.search(["UID", f"{lo}:{lo + 99_999}", *criteria]))
    return out


def locate(imap: Imap, state: MailboxState, cache: DateCache, wanted: list[tuple[int, str]]) -> dict[tuple[int, str], int]:
    """UIDs in the opened mailbox for (INTERNALDATE, X-Pm-Internal-Id)
    pairs: the cached date map narrows each to that second's messages, one
    header read of those decides. Without an internal id only a unique
    date match counts."""
    dates = cache.dates(imap, state, all_uids(imap, state))
    by_date: dict[int, list[int]] = {}
    for uid, when in dates.items():
        by_date.setdefault(when, []).append(uid)
    candidates = sorted({u for when, iid in wanted if iid for u in by_date.get(when, [])})
    iids = internal_ids(imap, candidates) if candidates else {}
    out: dict[tuple[int, str], int] = {}
    for when, iid in wanted:
        uids = by_date.get(when, [])
        match = [u for u in uids if iids.get(u) == iid] if iid else (uids if len(uids) == 1 else [])
        if match:
            out[(when, iid)] = match[0]
    return out


def open_refs(
    imap: Imap, cache: DateCache, mailbox: str, refs: list[MessageRef], write: bool = False
) -> tuple[MailboxState, dict[MessageRef, MessageRef | None]]:
    """Open one mailbox for several ids and say what each id names now:
    itself, its new UID after a UIDVALIDITY change, or None."""
    state = imap.select(mailbox) if write else imap.examine(mailbox)
    stale = [r for r in refs if r.uidvalidity != state.uidvalidity]
    found = locate(imap, state, cache, [(r.date, r.internal_id) for r in stale]) if stale else {}
    out: dict[MessageRef, MessageRef | None] = {}
    for r in refs:
        if r.uidvalidity == state.uidvalidity:
            out[r] = r
        else:
            uid = found.get((r.date, r.internal_id))
            out[r] = MessageRef(mailbox, state.uidvalidity, uid, r.date, r.internal_id) if uid else None
    return state, out


def open_ref(imap: Imap, cache: DateCache, ref: MessageRef, write: bool = False) -> tuple[MessageRef, MailboxState]:
    """Open the id's mailbox (EXAMINE, or SELECT for a write) and return the
    id as it stands now, or raise StaleId."""
    state, resolved = open_refs(imap, cache, ref.mailbox, [ref], write)
    now = resolved[ref]
    if now is None:
        raise StaleId(
            "the mailbox was resynchronized and this message could not be found again; search for it anew",
            mailbox=ref.mailbox,
        )
    return now, state


def check_identity(ref: MessageRef, headers: mime.Headers) -> None:
    """Refuse when the UID now holds a different message than the id names."""
    found = (headers.get("X-Pm-Internal-Id") or "").strip()
    if ref.internal_id and found and found != ref.internal_id:
        raise StaleId("this id no longer names the same message; search for it anew", mailbox=ref.mailbox)


def require(entries: list[Entry], ref: MessageRef) -> Entry:
    for entry in entries:
        if entry.uid == ref.uid:
            return entry
    raise NotFound("the message is no longer in that mailbox (moved or deleted); search for it anew")
