"""search: newest first, verified on decoded text, bounded, resumable.

Bridge's SEARCH matches raw bytes: no RFC 2047 in headers, no QP/base64 in
bodies (Bridge re-encodes every text part quoted-printable, so even an ASCII
word can be split by a soft line break). And on gluon every header or text
key loads and decrypts every message of the mailbox. So the server's SEARCH
is used only for what it answers from its database — flags — and the rest
happens here:

1. per mailbox, UID SEARCH on flags; INTERNALDATE for those UIDs (cached:
   immutable per UIDVALIDITY); date bounds and the cursor applied locally;
2. candidates sorted newest first across mailboxes (UIDs say nothing about
   dates: after Bridge's sync they run newest to oldest);
3. in batches: ENVELOPE + BODYSTRUCTURE (database-only) decide from, to,
   cc, subject, attachments and any text term found in the headers;
4. only then, the body of a still-undecided candidate: one partial fetch
   of its text part, decoded, HTML stripped, matched;
5. at the limit, or when the time/work budget runs out, stop and return a
   cursor (partial=true when the budget, not the limit, stopped it).

Duplicate views (All Mail, Starred, labels) are left out by default; a
message found twice (same Message-ID, date and size) is returned once."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from . import mime
from .errors import InvalidArgument
from .htmltext import html_to_text, plain_text
from .imapconn import EnvAddress, Imap, MailboxState
from .mailboxes import Mailboxes
from .messages import INTERNAL_ID_ITEM, DateCache, Summary, all_uids, flag_words, internal_id, iso, summaries
from .textmatch import TextQuery, fold

MAX_LIMIT = 50
BATCH = 100
TEXT_SCAN_BYTES = 64 * 1024
SNIPPET_BYTES = 2048
SNIPPET_CHARS = 240
TIME_BUDGET = 20.0
MAX_ENVELOPES = 20_000
MAX_BODIES = 1_500


def parse_when(value: str | None, name: str) -> int | None:
    """YYYY-MM-DD (a UTC day) or an ISO 8601 time with an offset."""
    if value is None or value == "":
        return None
    try:
        if len(value) == 10:
            d = date.fromisoformat(value)
            return int(datetime(d.year, d.month, d.day, tzinfo=UTC).timestamp())
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return int(dt.timestamp())
    except ValueError as exc:
        raise InvalidArgument(f"{name} must be YYYY-MM-DD or an ISO 8601 time") from exc


@dataclass
class Criteria:
    from_: TextQuery = field(default_factory=lambda: TextQuery(()))
    to: TextQuery = field(default_factory=lambda: TextQuery(()))
    cc: TextQuery = field(default_factory=lambda: TextQuery(()))
    subject: TextQuery = field(default_factory=lambda: TextQuery(()))
    text: TextQuery = field(default_factory=lambda: TextQuery(()))
    mailbox: str | None = None
    since: int | None = None
    before: int | None = None
    unread: bool | None = None
    starred: bool | None = None
    has_attachment: bool | None = None
    include_spam_trash: bool = False
    limit: int = 20

    def fingerprint(self) -> str:
        doc = {k: (list(v.terms) if isinstance(v, TextQuery) else v) for k, v in self.__dict__.items() if k != "limit"}
        return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:16]


SortKey = tuple[int, str, int]  # (-date, mailbox, -uid): ascending = newest first


def encode_cursor(crit: Criteria, key: SortKey) -> str:
    doc = {"v": 1, "f": crit.fingerprint(), "d": -key[0], "m": key[1], "u": -key[2]}
    return base64.urlsafe_b64encode(json.dumps(doc, separators=(",", ":")).encode()).decode().rstrip("=")


def decode_cursor(crit: Criteria, cursor: str | None) -> SortKey | None:
    if not cursor:
        return None
    try:
        doc = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if doc.get("v") != 1:
            raise ValueError
        key = (-int(doc["d"]), str(doc["m"]), -int(doc["u"]))
    except (ValueError, KeyError, TypeError) as exc:
        raise InvalidArgument("cursor is not one this server issued") from exc
    if doc.get("f") != crit.fingerprint():
        raise InvalidArgument("cursor belongs to a different search; repeat the same criteria with it")
    return key


def address_text(addrs: tuple[EnvAddress, ...]) -> str:
    return " ".join(f"{mime.decode_header(a.name)} {a.address}" for a in addrs)


def envelope_untrusted(s: Summary) -> dict[str, Any]:
    env = s.envelope

    def addrs(items: tuple[EnvAddress, ...]) -> list[dict[str, str]]:
        return [{"name": mime.decode_header(a.name), "address": a.address} for a in items]

    return {"from": addrs(env.from_), "to": addrs(env.to), "cc": addrs(env.cc), "subject": mime.decode_header(env.subject)}


def _header_match(s: Summary, crit: Criteria) -> tuple[bool, TextQuery]:
    env = s.envelope
    if crit.from_ and not crit.from_.matches(fold(address_text(env.from_))):
        return False, crit.text
    if crit.to and not crit.to.matches(fold(address_text(env.to) + " " + address_text(env.bcc))):
        return False, crit.text
    if crit.cc and not crit.cc.matches(fold(address_text(env.cc))):
        return False, crit.text
    subject = fold(mime.decode_header(env.subject))
    if crit.subject and not crit.subject.matches(subject):
        return False, crit.text
    if crit.has_attachment is not None and bool(s.attachments) != crit.has_attachment:
        return False, crit.text
    if not crit.text:
        return True, crit.text
    haystack = " ".join([subject, fold(address_text(env.from_)), fold(address_text(env.to)), fold(address_text(env.cc))])
    return True, crit.text.remaining(haystack)


def part_text(part: mime.Part, raw: bytes, partial: bool) -> str:
    data = mime.decode_partial_transfer(raw, part.cte) if partial else mime.decode_transfer(raw, part.cte)
    text = mime.decode_text(data, part.charset)
    return html_to_text(text) if part.subtype == "html" else plain_text(text)


def fetch_body_texts(imap: Imap, items: list[Summary], max_bytes: int) -> dict[int, str]:
    """uid → decoded body text (first text part, partial) for summaries of the open mailbox."""
    by_section: dict[str, dict[int, mime.Part]] = {}
    for s in items:
        if s.body:
            by_section.setdefault(s.body[0].section, {})[s.uid] = s.body[0]
    out: dict[int, str] = {}
    for section, parts in by_section.items():
        for e in imap.fetch(list(parts), [f"BODY.PEEK[{section}]<0.{max_bytes}>"]):
            raw = e.section(f"BODY[{section}]")
            if e.uid in parts and raw is not None:
                out[e.uid] = part_text(parts[e.uid], raw, partial=len(raw) >= max_bytes)
    return out


def snippet(text: str) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= SNIPPET_CHARS else flat[:SNIPPET_CHARS] + "…"


def finish(imap: Imap, found: list[Summary], texts: dict[tuple[str, int], str]) -> list[dict[str, Any]]:
    """Internal ids and snippets for the page, then the result rows."""
    iids: dict[tuple[str, int], str] = {}
    by_mb: dict[str, list[Summary]] = {}
    for s in found:
        by_mb.setdefault(s.mailbox, []).append(s)
    for name, items in by_mb.items():
        imap.examine(name)
        groups: dict[str, list[Summary]] = {}
        for s in items:
            section = s.body[0].section if s.body and (s.mailbox, s.uid) not in texts else ""
            groups.setdefault(section, []).append(s)
        for section, group in groups.items():
            fetch = [INTERNAL_ID_ITEM] + ([f"BODY.PEEK[{section}]<0.{SNIPPET_BYTES}>"] if section else [])
            parts = {s.uid: (s.body[0] if s.body else None) for s in group}
            for e in imap.fetch([s.uid for s in group], fetch):
                iids[(name, e.uid)] = internal_id(e)
                raw = e.section(f"BODY[{section}]") if section else None
                part = parts.get(e.uid)
                if raw is not None and part is not None:
                    texts[(name, e.uid)] = part_text(part, raw, partial=len(raw) >= SNIPPET_BYTES)
    rows = []
    for s in found:
        untrusted = envelope_untrusted(s)
        untrusted["snippet"] = snippet(texts.get((s.mailbox, s.uid), ""))
        rows.append(
            {
                "id": s.ref(iids.get((s.mailbox, s.uid), "")).encode(),
                "date": iso(s.date),
                "mailbox": s.mailbox,
                "flags": flag_words(s.flags),
                "has_attachments": bool(s.attachments),
                "size": s.size,
                "untrusted": untrusted,
            }
        )
    return rows


def flag_criteria(crit: Criteria) -> list[str]:
    terms = ["UNDELETED"]
    if crit.unread is True:
        terms.append("UNSEEN")
    elif crit.unread is False:
        terms.append("SEEN")
    if crit.starred is True:
        terms.append("FLAGGED")
    elif crit.starred is False:
        terms.append("UNFLAGGED")
    return terms


def run(
    imap: Imap, boxes: Mailboxes, cache: DateCache, crit: Criteria, cursor: str | None, clock=time.monotonic
) -> dict[str, Any]:
    started = clock()
    after = decode_cursor(crit, cursor)
    targets = [boxes.resolve(crit.mailbox)] if crit.mailbox else boxes.search_default(crit.include_spam_trash)
    flags = flag_criteria(crit)

    states: dict[str, MailboxState] = {}
    candidates: list[tuple[SortKey, str, int]] = []
    for mb in targets:
        state = imap.examine(mb.name)
        states[mb.name] = state
        if state.exists == 0:
            continue
        uids = all_uids(imap, state, flags)
        for uid, when in cache.dates(imap, state, uids).items():
            if crit.since is not None and when < crit.since:
                continue
            if crit.before is not None and when >= crit.before:
                continue
            key = (-when, mb.name, -uid)
            if after is not None and key <= after:
                continue
            candidates.append((key, mb.name, uid))
    candidates.sort()

    found: list[Summary] = []
    texts: dict[tuple[str, int], str] = {}
    seen: set[tuple[str, int, int]] = set()
    scanned = bodies = 0
    last_examined: SortKey | None = None
    stop_reason = "exhausted"
    i = 0
    while i < len(candidates):
        batch = candidates[i : i + BATCH]
        by_mb: dict[str, list[int]] = {}
        for _, name, uid in batch:
            by_mb.setdefault(name, []).append(uid)
        sums: dict[tuple[str, int], Summary] = {}
        for name, uids in by_mb.items():
            imap.examine(name)
            for s in summaries(imap, states[name], uids):
                sums[(name, s.uid)] = s

        decided: list[tuple[SortKey, Summary | None, TextQuery | None]] = []
        undecided: dict[str, list[Summary]] = {}
        for key, name, uid in batch:
            s = sums.get((name, uid))
            scanned += 1
            if s is None or s.key in seen:
                decided.append((key, None, None))
                continue
            seen.add(s.key)
            ok, remaining = _header_match(s, crit)
            if not ok:
                decided.append((key, None, None))
                continue
            decided.append((key, s, remaining if remaining else None))
            if remaining:
                undecided.setdefault(name, []).append(s)

        for name, items in undecided.items():
            imap.examine(name)
            bodies += len(items)
            for uid, text in fetch_body_texts(imap, items, TEXT_SCAN_BYTES).items():
                texts[(name, uid)] = text

        for key, s, remaining in decided:
            last_examined = key
            if s is None:
                continue
            if remaining is not None and not remaining.matches(fold(texts.get((s.mailbox, s.uid), ""))):
                continue
            found.append(s)
            if len(found) >= crit.limit:
                break
        if len(found) >= crit.limit:
            stop_reason = "limit"
            break
        i += len(batch)
        over = clock() - started > TIME_BUDGET or scanned >= MAX_ENVELOPES or bodies >= MAX_BODIES
        if i < len(candidates) and over:
            stop_reason = "budget"
            break

    rows = finish(imap, found, texts)
    next_cursor = None
    if stop_reason == "limit":
        last = (-found[-1].date, found[-1].mailbox, -found[-1].uid)
        if last != candidates[-1][0]:
            next_cursor = encode_cursor(crit, last)
    elif stop_reason == "budget" and last_examined is not None:
        next_cursor = encode_cursor(crit, last_examined)
    return {
        "results": rows,
        "partial": stop_reason == "budget",
        "next_cursor": next_cursor,
        "examined": scanned,
        "mailboxes": [m.name for m in targets],
    }
