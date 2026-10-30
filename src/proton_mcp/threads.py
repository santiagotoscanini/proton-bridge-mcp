"""get_thread: a conversation, oldest first.

IMAP has no conversation id and Bridge adds none, so a thread is rebuilt
from Message-ID links, without SEARCH (a HEADER search makes gluon decrypt
every message of the mailbox):

1. every real folder's messages within WINDOW of the seed, by the cached
   INTERNALDATE map;
2. their ENVELOPEs (database-only): Message-ID and In-Reply-To link
   ancestors and descendants, expanded to a fixed point from the seed's
   own Message-ID and References;
3. References are read (one header fetch each) only for same-subject
   messages the envelopes did not connect;
4. nothing linked at all: the same normalized subject between the same
   people, flagged heuristic=true.

Bridge appends <internal-id@protonmail.internalid> to every message's
References; that self reference is ignored."""

from __future__ import annotations

import re
from typing import Any

from . import mime
from .ids import MessageRef
from .imapconn import Imap
from .mailboxes import Mailboxes
from .messages import DateCache, Summary, all_uids, open_ref, require, summaries
from .search import finish
from .textmatch import fold

WINDOW = 180 * 86400
MAX_SCAN = 30_000
MAX_REFERENCE_READS = 200
SEED_HEADERS = "BODY.PEEK[HEADER.FIELDS (REFERENCES IN-REPLY-TO X-PM-INTERNAL-ID)]"
_PREFIX = re.compile(r"^\s*((re|aw|sv|antw|fwd?|wg|tr|rv|enc)\s*(\[\d+\])?\s*:\s*)+", re.I)


def normalized_subject(subject: str) -> str:
    return fold(_PREFIX.sub("", subject or ""))


def _ids(value: str | None, own_internal: str = "") -> set[str]:
    out = set()
    for mid in mime.message_ids(value):
        if own_internal and mid == own_internal + mime.INTERNAL_ID_DOMAIN:
            continue
        out.add(mid)
    return out


def _people(s: Summary) -> set[str]:
    env = s.envelope
    return {mime.normalize_address(a.address) for a in env.from_ + env.to + env.cc if a.address}


def run(imap: Imap, boxes: Mailboxes, cache: DateCache, ref: MessageRef, max_messages: int) -> dict[str, Any]:
    ref, state = open_ref(imap, cache, ref)
    entry = require(
        imap.fetch([ref.uid], [SEED_HEADERS]),
        ref,
    )
    headers = mime.Headers.from_bytes(entry.section("BODY[HEADER.FIELDS") or b"")
    seed_internal = (headers.get("X-Pm-Internal-Id") or "").strip()
    seed = summaries(imap, state, [ref.uid])[0]
    seed_ids = _ids(seed.envelope.message_id)
    linked = seed_ids | _ids(headers.get("References"), seed_internal) | _ids(headers.get("In-Reply-To"))

    window = WINDOW
    pool: dict[tuple[str, int], Summary] = {(seed.mailbox, seed.uid): seed}
    partial = False
    for mb in boxes.real():
        st = imap.examine(mb.name)
        if st.exists == 0:
            continue
        dates = cache.dates(imap, st, all_uids(imap, st))
        uids = [u for u, d in dates.items() if abs(d - seed.date) <= window and (mb.name, u) not in pool]
        if len(pool) + len(uids) > MAX_SCAN:
            partial = True
            uids = sorted(uids, key=lambda u: abs(dates[u] - seed.date))[: max(0, MAX_SCAN - len(pool))]
        for s in summaries(imap, st, uids):
            pool[(mb.name, s.uid)] = s

    def expand(ids: set[str]) -> set[tuple[str, int]]:
        members: set[tuple[str, int]] = {(seed.mailbox, seed.uid)}
        changed = True
        while changed:
            changed = False
            for key, s in pool.items():
                if key in members:
                    continue
                mids = _ids(s.envelope.message_id)
                irt = _ids(s.envelope.in_reply_to)
                if mids & ids or irt & ids:
                    members.add(key)
                    ids |= mids | irt
                    changed = True
        return members

    ids = set(linked)
    members = expand(ids)

    # Same subject, not linked by envelopes: read their References.
    subject = normalized_subject(mime.decode_header(seed.envelope.subject))
    if subject:
        stragglers = [
            k
            for k, s in pool.items()
            if k not in members and normalized_subject(mime.decode_header(s.envelope.subject)) == subject
        ][:MAX_REFERENCE_READS]
        by_mb: dict[str, list[int]] = {}
        for name, uid in stragglers:
            by_mb.setdefault(name, []).append(uid)
        for name, uids in by_mb.items():
            imap.examine(name)
            for e in imap.fetch(uids, ["BODY.PEEK[HEADER.FIELDS (REFERENCES X-PM-INTERNAL-ID)]"]):
                uid = e.uid
                h = mime.Headers.from_bytes(e.section("BODY[HEADER.FIELDS") or b"")
                refs = _ids(h.get("References"), (h.get("X-Pm-Internal-Id") or "").strip())
                if uid is not None and refs & ids:
                    ids |= refs | _ids(pool[(name, uid)].envelope.message_id)
        members = expand(ids)

    heuristic = False
    if len(members) == 1 and linked == seed_ids and subject:
        people = _people(seed)
        for key, s in pool.items():
            if normalized_subject(mime.decode_header(s.envelope.subject)) == subject and _people(s) & people:
                members.add(key)
        heuristic = len(members) > 1

    chosen: list[Summary] = []
    seen: set[tuple[str, int, int]] = set()
    for key in sorted(members, key=lambda k: (pool[k].date, k)):
        s = pool[key]
        if s.key in seen:
            continue
        seen.add(s.key)
        chosen.append(s)
    truncated = len(chosen) > max_messages
    if truncated:
        chosen = chosen[-max_messages:]
    rows = finish(imap, chosen, {})
    return {
        "messages": rows,
        "heuristic": heuristic,
        "truncated": truncated,
        "partial": partial,
        "window_days": WINDOW // 86400,
    }
