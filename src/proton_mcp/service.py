"""The 17 tools, each one IMAP session under its own command policy.

Everything a message says (headers, names, subjects, bodies, filenames,
calendar text) is returned under an `untrusted` key: data to read, never
instructions to follow."""

from __future__ import annotations

import base64
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import compose, ids, invite, mime, search, threads
from .errors import InvalidArgument, NotFound, Refused, TooLarge
from .guard import READ, Policy
from .htmltext import html_to_text, plain_text
from .ids import MessageRef
from .imapconn import Bridge, Imap, MailboxState
from .mailboxes import FOLDER_PREFIX, LABEL_PREFIX, MOVE_TARGET_ROLES, Mailboxes, is_folder, is_label
from .messages import (
    INTERNAL_ID_ITEM,
    DateCache,
    check_identity,
    flag_words,
    internal_id,
    iso,
    locate,
    open_ref,
    open_refs,
    real_attachments,
    require,
)
from .smtpsend import send_invite_reply
from .textmatch import TextQuery

MAX_IDS = 50
FULL_FETCH = 1024 * 1024  # whole message fetched at or below this size
MAX_TEXT_PART = 2 * 1024 * 1024
MAX_ATTACH_TEXT = 512 * 1024
MAX_ATTACH_IMAGE = 5 * 1024 * 1024
MAX_ATTACH_PDF = 10 * 1024 * 1024
MAX_FORWARD = 20 * 1024 * 1024
MAX_DRAFT_SOURCE = 25 * 1024 * 1024
_SECTION = re.compile(r"\d+(?:\.\d+){0,20}")
_BOOKKEEPING = {"x-pm-internal-id", "x-pm-gluon-id", "x-pm-date", "x-pm-external-id"}
_SECURITY = ("authentication-results", "received-spf", "arc-authentication-results")
_TEXTLIKE_EXT = (".txt", ".csv", ".tsv", ".json", ".ics", ".md", ".markdown", ".html", ".htm", ".xml", ".log", ".vcf", ".eml")
_TEXTLIKE_TYPES = {
    "application/json",
    "application/xml",
    "application/ics",
    "application/csv",
    "application/x-yaml",
    "application/yaml",
    "message/rfc822",
}
_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
DRAFT_FLAGS = ["\\Draft", "\\Seen"]
DRAFT_NOTE = "Saved in Drafts; nothing was sent. Open Proton Mail to review and send it."


# ── policies: what each tool may write ───────────────────────────────────


@dataclass
class _Ctx:
    """Mailbox facts a policy needs, filled by the tool's own LIST."""

    boxes: Mailboxes | None = None

    def role(self, name: str) -> str | None:
        m = self.boxes.get(name) if self.boxes else None
        return m.role if m and m.selectable else None


def _drafts_name(ctx: _Ctx) -> str | None:
    m = ctx.boxes.by_role("drafts") if ctx.boxes else None
    return m.name if m else None


def _append_draft(ctx: _Ctx) -> Callable[[str, frozenset[str]], bool]:
    return lambda box, flags: box == _drafts_name(ctx) and "\\Draft" in flags and flags <= {"\\Draft", "\\Seen"}


def _in_drafts(ctx: _Ctx) -> Callable[[str], bool]:
    return lambda box: box == _drafts_name(ctx)


def _deleted_only(pred: Callable[[str], bool]) -> Callable[[str, str, frozenset[str]], bool]:
    return lambda sel, op, flags: pred(sel) and flags == {"\\Deleted"}


def mark_policy() -> Policy:
    return Policy(
        "mark",
        select=lambda box: True,
        store=lambda sel, op, flags: bool(flags) and flags <= {"\\Seen", "\\Flagged"},
    )


def move_policy(ctx: _Ctx) -> Policy:
    def target(box: str) -> bool:
        role = ctx.role(box)
        return role in MOVE_TARGET_ROLES or role == "folder"

    return Policy("move", select=lambda box: ctx.role(box) is not None, move_to=target, copy_to=target)


def label_policy(ctx: _Ctx) -> Policy:
    def label(box: str) -> bool:
        return ctx.role(box) == "label"

    return Policy(
        "label",
        select=lambda box: ctx.role(box) is not None,
        copy_to=label,
        store=_deleted_only(label),
        expunge_in=label,
    )


def folders_policy() -> Policy:
    return Policy(
        "folders",
        create=is_folder,
        rename=lambda old, new: is_folder(old) and is_folder(new),
        delete=is_folder,
    )


def _flat_label(name: str) -> bool:
    return is_label(name) and "/" not in name[len(LABEL_PREFIX) :]


def labels_policy() -> Policy:
    return Policy(
        "labels",
        create=_flat_label,
        rename=lambda old, new: _flat_label(old) and _flat_label(new),
        delete=_flat_label,
    )


def draft_policy(ctx: _Ctx) -> Policy:
    return Policy("draft", append=_append_draft(ctx))


def replace_draft_policy(ctx: _Ctx) -> Policy:
    return Policy(
        "update_draft",
        append=_append_draft(ctx),
        select=_in_drafts(ctx),
        store=_deleted_only(_in_drafts(ctx)),
        expunge_in=_in_drafts(ctx),
    )


def discard_policy(ctx: _Ctx) -> Policy:
    return Policy(
        "discard_draft",
        select=_in_drafts(ctx),
        store=_deleted_only(_in_drafts(ctx)),
        expunge_in=_in_drafts(ctx),
    )


# ── one message, loaded ──────────────────────────────────────────────────


@dataclass
class Loaded:
    ref: MessageRef
    state: MailboxState
    headers: mime.Headers
    root: mime.Part
    flags: list[str]
    date: int
    size: int
    local: bool  # the whole message is in memory
    imap: Imap = field(repr=False)

    def part_bytes(self, part: mime.Part, cap: int) -> tuple[bytes, bool]:
        """Decoded content of a part, at most about cap bytes; (data, truncated)."""
        if self.local and part.local is not None:
            data = part.decoded()
            return data[:cap], len(data) > cap
        encoded_cap = cap * 4 // 3 + 4096 if part.cte.lower() == "base64" else cap + 4096
        item = f"BODY.PEEK[{part.section}]" + (f"<0.{encoded_cap}>" if part.size > encoded_cap else "")
        entry = require(self.imap.fetch([self.ref.uid], [item]), self.ref)
        raw = entry.section(f"BODY[{part.section}]") or b""
        truncated = part.size > encoded_cap
        data = mime.decode_partial_transfer(raw, part.cte) if truncated else mime.decode_transfer(raw, part.cte)
        return data[:cap], truncated or len(data) > cap

    def text(self) -> tuple[str, bool, str | None]:
        """(body text, undecryptable, format) — plain preferred, HTML stripped."""
        if mime.is_pgp_mime_fallback(self.root):
            return "[This message is PGP/MIME encrypted and Bridge could not decrypt it.]", True, None
        texts, undecryptable, fmt = [], False, None
        for part in mime.body_parts(self.root)[:5]:
            data, _ = self.part_bytes(part, MAX_TEXT_PART)
            if mime.is_undecryptable_text(data):
                undecryptable = True
                texts.append("[Bridge could not decrypt this message's body.]")
                continue
            decoded = mime.decode_text(data, part.charset)
            if part.subtype == "html":
                texts.append(html_to_text(decoded))
                fmt = fmt or "html"
            else:
                text = plain_text(decoded)
                if not text.strip():
                    alt = mime.html_alternative(self.root, part)
                    if alt is not None:
                        html, _ = self.part_bytes(alt, MAX_TEXT_PART)
                        text = html_to_text(mime.decode_text(html, alt.charset))
                texts.append(text)
                fmt = fmt or "plain"
        return "\n\n".join(t for t in texts if t), undecryptable, fmt


def load(imap: Imap, cache: DateCache, ref: MessageRef, full_cap: int | None = None) -> Loaded:
    ref, state = open_ref(imap, cache, ref)
    entry = require(
        imap.fetch([ref.uid], ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "BODYSTRUCTURE", "BODY.PEEK[HEADER]"]),
        ref,
    )
    headers = mime.Headers.from_bytes(entry.section("BODY[HEADER]") or b"")
    check_identity(ref, headers)
    internal = (headers.get("X-Pm-Internal-Id") or "").strip()
    if internal and not ref.internal_id:
        ref = MessageRef(ref.mailbox, ref.uidvalidity, ref.uid, ref.date, internal)
    size = entry.size or 0

    date = entry.date or 0
    flags = entry.flags
    if size <= (FULL_FETCH if full_cap is None else full_cap):
        whole = require(imap.fetch([ref.uid], ["BODY.PEEK[]"]), ref)
        raw = whole.section("BODY[]") or b""
        _, root = mime.parse_message(raw)
        local = True
    else:
        root = mime.from_bodystructure(entry.bodystructure)
        local = False
    return Loaded(ref, state, headers, root, flags, date, size, local, imap)


def delivered_to(headers: mime.Headers, own: tuple[str, ...]) -> str | None:
    """Which of the account's addresses the message reached (account spelling)."""
    mine = {mime.normalize_address(a): a for a in own}
    for name in ("Delivered-To", "X-Original-To", "To", "Cc", "Bcc"):
        for addr in headers.addresses(name):
            hit = mine.get(mime.normalize_address(addr.address))
            if hit:
                return hit
    return None


def _addr_list(addrs: list[mime.Address]) -> list[dict[str, str]]:
    return [a.to_dict() for a in addrs]


def _security(headers: mime.Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in headers.names():
        low = name.lower()
        if (low.startswith("x-pm-") and low not in _BOOKKEEPING) or low in _SECURITY:
            if name not in out:
                out[name] = (headers.get(name) or "")[:500]
        if len(out) >= 30:
            break
    return out


def _attachment_rows(root: mime.Part) -> list[dict[str, Any]]:
    rows = []
    for p in real_attachments(root):
        rows.append(
            {
                "part": p.section,
                "content_type": p.content_type,
                "size": p.decoded_size_estimate,
                "inline": p.disposition == "inline",
                "undecryptable": mime.is_undecryptable_attachment(p),
                "untrusted": {"filename": p.filename or ""},
            }
        )
    return rows


def forwardable(root: mime.Part) -> list[mime.Part]:
    """What a forward carries: every non-body part, inline images included
    (the forward's body is plain text, so they would otherwise be lost)."""
    return [p for p in mime.attachments(root, mime.body_parts(root)) if p.content_type != "application/pgp-signature"]


def _recipients_of(headers: mime.Headers) -> list[str]:
    return [a.address for a in headers.addresses("Delivered-To", "X-Original-To", "To", "Cc")]


def _invite(loaded: Loaded, own: tuple[str, ...]) -> invite.Invite | None:
    part = mime.calendar_part(loaded.root)
    if part is None:
        return None
    data, truncated = loaded.part_bytes(part, invite.MAX_ICS)
    if truncated:
        raise InvalidArgument("the calendar part is too large to read")
    return invite.parse(data, own, _recipients_of(loaded.headers))


def _decode_ids(values: Any) -> list[MessageRef]:
    if not isinstance(values, list) or not values:
        raise InvalidArgument("ids must be a non-empty list")
    if len(values) > MAX_IDS:
        raise InvalidArgument(f"at most {MAX_IDS} ids per call")
    refs = [ids.decode(v) for v in values]
    return list(dict.fromkeys(refs))


def _group(refs: list[MessageRef]) -> dict[str, list[MessageRef]]:
    out: dict[str, list[MessageRef]] = {}
    for r in refs:
        out.setdefault(r.mailbox, []).append(r)
    return out


def _mailbox_name(prefix: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgument("a name is required")
    name = value.strip().strip("/")
    if not name.startswith(prefix):
        name = prefix + name
    if re.search(r"[\x00-\x1f\x7f*%]", name) or "//" in name or len(name) > 300:
        raise InvalidArgument("that name cannot be used")
    return name


# ── the tools ────────────────────────────────────────────────────────────


class Mail:
    def __init__(
        self,
        bridge: Bridge,
        cache: DateCache | None = None,
        send: Callable[..., None] = send_invite_reply,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.bridge = bridge
        self.cache = cache or DateCache()
        self._send = send
        self._now = now

    def _own(self) -> tuple[str, ...]:
        return self.bridge.credentials().addresses

    # 1
    def list_mailboxes(self) -> dict[str, Any]:
        own = self._own()

        def go(imap: Imap) -> dict[str, Any]:
            boxes = Mailboxes(imap.list())
            rows = []
            for m in boxes.selectable():
                st = imap.status(m.name)
                rows.append({"name": m.name, "role": m.role, "messages": st.get("MESSAGES", 0), "unseen": st.get("UNSEEN", 0)})
            return {"addresses": list(own), "mailboxes": rows}

        return self.bridge.run(READ, go)

    # 2
    def search(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = int(args.get("limit") or 20)
        if not 1 <= limit <= search.MAX_LIMIT:
            raise InvalidArgument(f"limit must be 1..{search.MAX_LIMIT}")
        crit = search.Criteria(
            from_=TextQuery.parse(args.get("from") or ""),
            to=TextQuery.parse(args.get("to") or ""),
            cc=TextQuery.parse(args.get("cc") or ""),
            subject=TextQuery.parse(args.get("subject") or ""),
            text=TextQuery.parse(args.get("text") or ""),
            mailbox=args.get("mailbox") or None,
            since=search.parse_when(args.get("since"), "since"),
            before=search.parse_when(args.get("before"), "before"),
            unread=args.get("unread"),
            starred=args.get("starred"),
            has_attachment=args.get("has_attachment"),
            include_spam_trash=bool(args.get("include_spam_trash", False)),
            limit=limit,
        )
        return self.bridge.run(READ, lambda imap: search.run(imap, Mailboxes(imap.list()), self.cache, crit, args.get("cursor")))

    # 3
    def get_message(self, id: str, max_chars: int = 20000, offset: int = 0) -> dict[str, Any]:
        if not 1 <= max_chars <= 100_000 or offset < 0:
            raise InvalidArgument("max_chars must be 1..100000 and offset >= 0")
        ref = ids.decode(id)
        own = self._own()

        def go(imap: Imap) -> dict[str, Any]:
            msg = load(imap, self.cache, ref)
            text, undecryptable, fmt = msg.text()
            page = text[offset : offset + max_chars]
            end = offset + len(page)
            h = msg.headers
            out: dict[str, Any] = {
                "id": msg.ref.encode(),
                "mailbox": msg.ref.mailbox,
                "date": iso(msg.date),
                "flags": flag_words(msg.flags),
                "size": msg.size,
                "delivered_to": delivered_to(h, own),
                "undecryptable": undecryptable,
                "body_format": fmt,
                "text_length": len(text),
                "truncated": end < len(text),
                "next_offset": end if end < len(text) else None,
                "attachments": _attachment_rows(msg.root),
                "untrusted": {
                    "headers": {
                        "from": _addr_list(h.addresses("From")),
                        "to": _addr_list(h.addresses("To")),
                        "cc": _addr_list(h.addresses("Cc")),
                        "reply_to": _addr_list(h.addresses("Reply-To")),
                        "subject": h.get("Subject") or "",
                        "date": h.get("Date") or "",
                        "message_id": h.get("Message-ID") or "",
                        "in_reply_to": h.get("In-Reply-To") or "",
                        "references": mime.message_ids(h.get("References"))[-20:],
                        "list_unsubscribe": h.get("List-Unsubscribe") or "",
                        "delivered_to": h.get_all("Delivered-To")[:5],
                    },
                    "text": page,
                    "security": _security(h),
                },
            }
            try:
                inv = _invite(msg, own)
            except InvalidArgument as exc:
                out["invite"] = {"error": exc.message}
            else:
                if inv is not None:
                    data = inv.to_dict()
                    out["invite"] = {
                        "answerable_here": data.pop("answerable_here"),
                        "method": data.pop("method"),
                        "your_status": data.pop("your_status"),
                        "invited_address": data.pop("invited_address"),
                        "untrusted": data,
                    }
            return out

        return self.bridge.run(READ, go)

    # 4
    def get_thread(self, id: str, max_messages: int = 50) -> dict[str, Any]:
        if not 1 <= max_messages <= 100:
            raise InvalidArgument("max_messages must be 1..100")
        ref = ids.decode(id)
        return self.bridge.run(READ, lambda imap: threads.run(imap, Mailboxes(imap.list()), self.cache, ref, max_messages))

    # 5
    def get_attachment(self, id: str, part: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """(metadata, payloads) where a payload is {"kind": text|image|pdf, ...}."""
        if not isinstance(part, str) or not _SECTION.fullmatch(part):
            raise InvalidArgument("part must be a part number such as 2 or 1.2")
        ref = ids.decode(id)

        def go(imap: Imap) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            msg = load(imap, self.cache, ref, full_cap=0)  # structure only; fetch just this part
            p = msg.root.find(part)
            if p is None:
                raise NotFound(f"message has no part {part}")
            name = (p.filename or "").lower()
            ctype = p.content_type
            meta: dict[str, Any] = {
                "id": msg.ref.encode(),
                "part": part,
                "content_type": ctype,
                "size": p.decoded_size_estimate,
                "undecryptable": mime.is_undecryptable_attachment(p),
                "untrusted": {"filename": p.filename or ""},
            }
            if ctype == "application/pdf" or name.endswith(".pdf"):
                if p.decoded_size_estimate > MAX_ATTACH_PDF:
                    raise TooLarge(f"PDF larger than {MAX_ATTACH_PDF // 1024 // 1024} MB; not returned", **meta)
                data, _ = msg.part_bytes(p, MAX_ATTACH_PDF + 1)
                meta["delivered_as"] = "pdf"
                return meta, [{"kind": "pdf", "data": data, "uri": f"proton-mail://attachment/{msg.ref.uid}/{part}"}]
            if ctype in _IMAGE_TYPES:
                if p.decoded_size_estimate > MAX_ATTACH_IMAGE:
                    raise TooLarge(f"image larger than {MAX_ATTACH_IMAGE // 1024 // 1024} MB; not returned", **meta)
                data, _ = msg.part_bytes(p, MAX_ATTACH_IMAGE + 1)
                meta["delivered_as"] = "image"
                return meta, [{"kind": "image", "data": data, "mime": ctype}]
            if p.maintype == "text" or ctype in _TEXTLIKE_TYPES or name.endswith(_TEXTLIKE_EXT):
                data, truncated = msg.part_bytes(p, MAX_ATTACH_TEXT)
                if b"\x00" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
                    meta["delivered_as"] = "metadata"
                    meta["note"] = "binary content; not returned as text"
                    return meta, []
                if ctype == "message/rfc822":
                    text = _rfc822_text(data)
                else:
                    text = mime.decode_text(data, p.charset)
                    if p.subtype == "html" or name.endswith((".html", ".htm")):
                        text = html_to_text(text)
                meta["delivered_as"] = "text"
                meta["truncated"] = truncated
                meta["untrusted"]["text"] = text
                return meta, []
            meta["delivered_as"] = "metadata"
            meta["note"] = "this type is not returned; only its metadata"
            return meta, []

        return self.bridge.run(READ, go)

    # 6
    def mark(self, ids_: Any, read: bool | None = None, starred: bool | None = None) -> dict[str, Any]:
        refs = _decode_ids(ids_)
        if read is None and starred is None:
            raise InvalidArgument("set read and/or starred")

        def go(imap: Imap) -> dict[str, Any]:
            results = []
            for mailbox, group in _group(refs).items():
                state, resolved = open_refs(imap, self.cache, mailbox, group, write=True)
                live = {r: n for r, n in resolved.items() if n is not None}
                uids = [n.uid for n in live.values()]
                flags: dict[int, list[str]] = {}
                if uids:
                    for value, flag in ((read, "\\Seen"), (starred, "\\Flagged")):
                        if value is not None:
                            flags.update(imap.store(uids, bool(value), [flag]))
                    missing = [u for u in uids if u not in flags]
                    if missing:
                        for e in imap.fetch(missing, ["FLAGS"]):
                            flags[e.uid] = e.flags
                for r in group:
                    n = resolved.get(r)
                    if n is None or n.uid not in flags:
                        results.append({"id": r.encode(), "ok": False, "error": "not found in its mailbox"})
                        continue
                    words = flag_words(flags[n.uid])
                    ok = (read is None or ("read" in words) == read) and (starred is None or ("starred" in words) == starred)
                    results.append({"id": n.encode(), "ok": ok, "flags": words})
            return {"results": results}

        return self.bridge.run(mark_policy(), go)

    # 7
    def move(self, ids_: Any, to: str) -> dict[str, Any]:
        refs = _decode_ids(ids_)
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            dest = ctx.boxes.move_target(to)
            results = []
            for mailbox, group in _group(refs).items():
                src = ctx.boxes.get(mailbox)
                if src is None or not src.selectable:
                    results.extend({"id": r.encode(), "ok": False, "error": "its mailbox no longer exists"} for r in group)
                    continue
                if src.name == dest.name:
                    results.extend({"id": r.encode(), "ok": True, "note": "already there"} for r in group)
                    continue
                state, resolved = open_refs(imap, self.cache, mailbox, group, write=True)
                live = [n for n in resolved.values() if n is not None]
                mapping: dict[int, int] = {}
                dest_validity = 0
                if live:
                    # From a view (All Mail, Starred, a label) a MOVE would also
                    # drop that view's label; COPY into a folder moves the message
                    # in Proton (one folder per message) and keeps its labels.
                    op = imap.copy if src.is_view else imap.move
                    code = op([n.uid for n in live], dest.name)
                    if code is not None:
                        mapping, dest_validity = code.mapping(), code.uidvalidity
                for r in group:
                    n = resolved.get(r)
                    new_uid = mapping.get(n.uid) if n else None
                    if n is None or new_uid is None:
                        results.append(
                            {"id": r.encode(), "ok": False, "error": "Bridge did not move it (moved or deleted meanwhile?)"}
                        )
                    else:
                        results.append(
                            {"id": MessageRef(dest.name, dest_validity, new_uid, r.date, r.internal_id).encode(), "ok": True}
                        )
            return {"to": dest.name, "results": results}

        return self.bridge.run(move_policy(ctx), go)

    # 8
    def label(self, ids_: Any, add: list[str] | None = None, remove: list[str] | None = None) -> dict[str, Any]:
        refs = _decode_ids(ids_)
        add_names = [_mailbox_name(LABEL_PREFIX, n) for n in add or []]
        remove_names = [_mailbox_name(LABEL_PREFIX, n) for n in remove or []]
        if not add_names and not remove_names:
            raise InvalidArgument("name labels to add and/or remove")
        if set(add_names) & set(remove_names):
            raise InvalidArgument("a label cannot be both added and removed")
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            for name in add_names + remove_names:
                if ctx.role(name) != "label":
                    raise NotFound(f"no label {name!r}; create it with the labels tool")
            report: dict[str, list[dict[str, Any]]] = {}
            for name in add_names:
                rows = report.setdefault(name, [])
                for mailbox, group in _group(refs).items():
                    state, resolved = open_refs(imap, self.cache, mailbox, group, write=True)
                    live = [n for n in resolved.values() if n is not None]
                    code = imap.copy([n.uid for n in live], name) if live else None
                    mapping = code.mapping() if code else {}
                    for r in group:
                        n = resolved.get(r)
                        ok = n is not None and n.uid in mapping
                        rows.append({"id": r.encode(), "ok": ok, "action": "added"})
            for name in remove_names:
                rows = report.setdefault(name, [])
                state, _ = open_refs(imap, self.cache, name, [], write=True)
                inside = {r: r for r in refs if r.mailbox == name and r.uidvalidity == state.uidvalidity}
                elsewhere = [r for r in refs if r not in inside]

                found = locate(imap, state, self.cache, [(r.date, r.internal_id) for r in elsewhere]) if elsewhere else {}
                uids = {r: inside[r].uid if r in inside else found.get((r.date, r.internal_id)) for r in refs}
                targets = sorted({u for u in uids.values() if u})
                if targets:
                    # Expunging from a label mailbox only unlabels: Bridge's
                    # connector calls Proton's unlabel and deletes nothing
                    # outside Trash/Drafts (imapservice/connector.go).
                    imap.store(targets, True, ["\\Deleted"], silent=True)
                    imap.expunge(targets)
                    still = {
                        e.uid for e in imap.fetch(targets, ["FLAGS"])
                    }  # a UID search key errors on an empty mailbox in gluon
                else:
                    still = set()
                for r in refs:
                    u = uids[r]
                    if u is None:
                        rows.append({"id": r.encode(), "ok": True, "action": "removed", "note": "did not carry the label"})
                    else:
                        rows.append({"id": r.encode(), "ok": u not in still, "action": "removed"})
            return {"results": report}

        return self.bridge.run(label_policy(ctx), go)

    # 9, 10
    def _structure(self, prefix: str, policy: Policy, action: str, name: Any, new_name: Any) -> dict[str, Any]:
        target = _mailbox_name(prefix, name)
        renamed = _mailbox_name(prefix, new_name) if action == "rename" else None
        if action not in ("create", "rename", "delete"):
            raise InvalidArgument("action must be create, rename or delete")
        if prefix == LABEL_PREFIX and any("/" in n[len(LABEL_PREFIX) :] for n in (target, renamed or target)):
            raise InvalidArgument("labels cannot be nested")

        def go(imap: Imap) -> dict[str, Any]:
            before = Mailboxes(imap.list())
            if action == "create":
                if before.get(target):
                    raise Refused(f"{target!r} already exists")
                imap.create(target)
            elif action == "rename":
                if not before.get(target):
                    raise NotFound(f"no {target!r}")
                if before.get(renamed):  # type: ignore[arg-type]
                    raise Refused(f"{renamed!r} already exists")
                imap.rename(target, renamed)  # type: ignore[arg-type]
            else:
                if not before.get(target):
                    raise NotFound(f"no {target!r}")
                imap.delete(target)
            after = Mailboxes(imap.list())
            out: dict[str, Any] = {"action": action, "name": target}
            if action == "create":
                out["ok"] = after.get(target) is not None
            elif action == "rename":
                out["new_name"] = renamed
                out["ok"] = after.get(renamed) is not None and after.get(target) is None  # type: ignore[arg-type]
            else:
                out["ok"] = after.get(target) is None
                out["also_removed"] = [m.name for m in before.all if m.name.startswith(target + "/") and not after.get(m.name)]
            return out

        return self.bridge.run(policy, go)

    def folders(self, action: str, name: str, new_name: str | None = None) -> dict[str, Any]:
        return self._structure(FOLDER_PREFIX, folders_policy(), action, name, new_name)

    def labels(self, action: str, name: str, new_name: str | None = None) -> dict[str, Any]:
        return self._structure(LABEL_PREFIX, labels_policy(), action, name, new_name)

    # drafts
    def _append_draft(self, imap: Imap, ctx: _Ctx, data: bytes) -> str | None:
        drafts = ctx.boxes.drafts()  # type: ignore[union-attr]
        code = imap.append(drafts.name, DRAFT_FLAGS, data)
        if code is None or not code.dest:
            return None
        state = imap.examine(drafts.name)
        uid = code.dest[0]
        entry = next(iter(imap.fetch([uid], ["INTERNALDATE", INTERNAL_ID_ITEM])), None)
        if entry is None:
            return None

        date = entry.date or 0
        iid = internal_id(entry)
        return MessageRef(drafts.name, state.uidvalidity, uid, date, iid).encode()

    def _draft_result(self, draft_id: str | None, msg: Any) -> dict[str, Any]:
        h = mime.Headers(list(msg.items()))  # a composed EmailMessage: values are already text
        return {
            "draft_id": draft_id,
            "from": (h.addresses("From") or [mime.Address("", "")])[0].address,
            "to": [a.address for a in h.addresses("To")],
            "cc": [a.address for a in h.addresses("Cc")],
            "bcc": [a.address for a in h.addresses("Bcc")],
            "subject": h.get("Subject") or "",
            "note": DRAFT_NOTE if draft_id else "Bridge stored the draft but did not report its UID; find it in Drafts.",
        }

    # 11
    def draft_email(self, args: dict[str, Any]) -> dict[str, Any]:
        own = self._own()
        sender = compose.choose_from(args.get("from"), own, own[0])
        to = compose.parse_recipients(args.get("to"), "to")
        cc = compose.parse_recipients(args.get("cc"), "cc")
        bcc = compose.parse_recipients(args.get("bcc"), "bcc")
        if not to and not cc and not bcc:
            raise InvalidArgument("a draft needs at least one recipient")
        msg = compose.message(sender, to, cc, bcc, args.get("subject") or "", args.get("body") or "", self._now())
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            return self._draft_result(self._append_draft(imap, ctx, compose.to_bytes(msg)), msg)

        return self.bridge.run(draft_policy(ctx), go)

    # 12
    def draft_reply(
        self, id: str, body: str, reply_all: bool = False, quote: bool = True, from_: str | None = None
    ) -> dict[str, Any]:
        ref = ids.decode(id)
        own = self._own()
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            orig = load(imap, self.cache, ref)
            to, cc = compose.reply_recipients(orig.headers, own, reply_all)
            if not to:
                raise Refused("the original names no one to reply to")
            sender = compose.choose_from(from_, own, delivered_to(orig.headers, own) or own[0])
            text = body
            if quote:
                quoted_text, _, _ = orig.text()
                text = f"{body}\n\n{compose.quoted(orig.headers, quoted_text)}"
            msg = compose.message(sender, to, cc, [], compose.reply_subject(orig.headers.get("Subject") or ""), text, self._now())
            irt, refs = compose.thread_headers(orig.headers)
            if irt:
                msg["In-Reply-To"] = irt
                msg["References"] = refs
            return self._draft_result(self._append_draft(imap, ctx, compose.to_bytes(msg)), msg)

        return self.bridge.run(draft_policy(ctx), go)

    # 13
    def draft_forward(
        self,
        id: str,
        to: list[str],
        body: str = "",
        include_attachments: bool = True,
        cc: list[str] | None = None,
        from_: str | None = None,
    ) -> dict[str, Any]:
        ref = ids.decode(id)
        own = self._own()
        to_addrs = compose.parse_recipients(to, "to")
        cc_addrs = compose.parse_recipients(cc, "cc")
        if not to_addrs:
            raise InvalidArgument("a forward needs at least one recipient in to")
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            orig = load(imap, self.cache, ref)
            sender = compose.choose_from(from_, own, delivered_to(orig.headers, own) or own[0])
            original_text, _, _ = orig.text()
            text = f"{body}\n\n{compose.forwarded_block(orig.headers, original_text)}".lstrip("\n")
            msg = compose.message(
                sender, to_addrs, cc_addrs, [], compose.forward_subject(orig.headers.get("Subject") or ""), text, self._now()
            )
            skipped: list[str] = []
            files: list[compose.FileAttachment] = []
            if include_attachments:
                total = 0
                for p in forwardable(orig.root):
                    if mime.is_undecryptable_attachment(p):
                        skipped.append(p.section)
                        continue
                    total += p.decoded_size_estimate
                    if total > MAX_FORWARD:
                        raise TooLarge(f"attachments exceed {MAX_FORWARD // 1024 // 1024} MB; forward without them")
                    data, _ = orig.part_bytes(p, MAX_FORWARD)
                    files.append(compose.FileAttachment(p.filename or f"part-{p.section}", p.content_type, data))
                compose.attach(msg, files)
            out = self._draft_result(self._append_draft(imap, ctx, compose.to_bytes(msg)), msg)
            out["attachments"] = len(files)
            if skipped:
                out["skipped_undecryptable_parts"] = skipped
            return out

        return self.bridge.run(draft_policy(ctx), go)

    def _invite_reply(self, imap: Imap, ref: MessageRef, response: str, comment: str | None) -> tuple[invite.Invite, Any, str]:
        own = self._own()
        orig = load(imap, self.cache, ref)
        inv = _invite(orig, own)
        if inv is None:
            raise Refused("this message carries no calendar invitation")
        invite.check_answerable(inv)
        sender = compose.choose_from(inv.invited_address, own, own[0])
        ics = invite.build_reply(inv, response, comment, self._now())
        prefix = invite.SUBJECT_PREFIX[response]
        subject = f"{prefix}: {inv.summary}" if inv.summary else prefix
        body = (comment or "").strip() or f"{prefix}: {inv.summary}".strip(": ")
        msg = compose.invite_reply_message(sender, "", inv.organizer, inv.organizer_name, subject, body, ics, self._now())
        return inv, msg, sender

    # 14
    def draft_invite_response(self, id: str, response: str, comment: str | None = None) -> dict[str, Any]:
        if response not in invite.PARTSTAT:
            raise InvalidArgument("response must be accept, tentative or decline")
        ref = ids.decode(id)
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            inv, msg, _ = self._invite_reply(imap, ref, response, comment)
            out = self._draft_result(self._append_draft(imap, ctx, compose.to_bytes(msg)), msg)
            out["response"] = response
            return out

        return self.bridge.run(draft_policy(ctx), go)

    # 15
    def update_draft(self, args: dict[str, Any]) -> dict[str, Any]:
        ref = ids.decode(args.get("id"))
        own = self._own()
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            drafts = ctx.boxes.drafts()
            if ref.mailbox != drafts.name:
                raise Refused("update_draft only changes messages in Drafts")
            old = load(imap, self.cache, ref, full_cap=MAX_DRAFT_SOURCE)
            if not old.local:
                raise TooLarge("this draft is too large to rewrite here")
            if "\\Draft" not in old.flags:
                raise Refused("that message in Drafts is not a draft")
            h = old.headers
            sender = compose.choose_from(args.get("from"), own, (h.addresses("From") or [mime.Address("", own[0])])[0].address)
            to = compose.parse_recipients(args["to"], "to") if "to" in args else h.addresses("To")
            cc = compose.parse_recipients(args["cc"], "cc") if "cc" in args else h.addresses("Cc")
            bcc = compose.parse_recipients(args["bcc"], "bcc") if "bcc" in args else h.addresses("Bcc")
            subject = args["subject"] if "subject" in args else (h.get("Subject") or "")
            body = args["body"] if "body" in args else old.text()[0]
            msg = compose.message(sender, to, cc, bcc, subject, body, self._now())
            for name in ("In-Reply-To", "References"):
                if h.get(name):
                    msg[name] = re.sub(r"[\r\n]+", " ", h.get(name) or "")
            files = []
            for p in real_attachments(old.root):
                data, _ = old.part_bytes(p, MAX_FORWARD)
                files.append(compose.FileAttachment(p.filename or f"part-{p.section}", p.content_type, data))
            compose.attach(msg, files)
            new_id = self._append_draft(imap, ctx, compose.to_bytes(msg))
            if new_id is None:
                raise Refused("Bridge did not confirm the new version; the old draft is kept")
            state, resolved = open_refs(imap, self.cache, drafts.name, [old.ref], write=True)
            now = resolved[old.ref]
            removed = False
            if now is not None:
                imap.store([now.uid], True, ["\\Deleted"], silent=True)
                imap.expunge([now.uid])
                removed = not imap.fetch([now.uid], ["FLAGS"])
            out = self._draft_result(new_id, msg)
            out["old_version_removed"] = removed
            return out

        return self.bridge.run(replace_draft_policy(ctx), go)

    # 16
    def discard_draft(self, id: str) -> dict[str, Any]:
        ref = ids.decode(id)
        ctx = _Ctx()

        def go(imap: Imap) -> dict[str, Any]:
            ctx.boxes = Mailboxes(imap.list())
            drafts = ctx.boxes.drafts()
            if ref.mailbox != drafts.name:
                raise Refused("discard_draft only removes messages in Drafts")
            now, state = open_ref(imap, self.cache, ref, write=True)
            entry = require(imap.fetch([now.uid], ["FLAGS", INTERNAL_ID_ITEM]), now)
            check_identity(now, mime.Headers.from_bytes(entry.section("BODY[HEADER.FIELDS") or b""))
            if "\\Draft" not in entry.flags:
                raise Refused("that message in Drafts is not a draft")
            imap.store([now.uid], True, ["\\Deleted"], silent=True)
            imap.expunge([now.uid])
            return {"ok": not imap.fetch([now.uid], ["FLAGS"]), "id": now.encode()}

        return self.bridge.run(discard_policy(ctx), go)

    # 17
    def respond_to_invite(self, id: str, response: str) -> dict[str, Any]:
        if response not in invite.PARTSTAT:
            raise InvalidArgument("response must be accept, tentative or decline")
        ref = ids.decode(id)
        inv, msg, sender = self.bridge.run(READ, lambda imap: self._invite_reply(imap, ref, response, None))
        creds = self.bridge.credentials()
        self._send(creds, sender, inv.organizer, compose.to_bytes(msg))
        return {
            "sent": True,
            "response": response,
            "from": sender,
            "to": inv.organizer,
            "untrusted": {"summary": inv.summary, "start": inv.start},
        }


def _rfc822_text(data: bytes) -> str:
    headers, root = mime.parse_message(data)
    parts = []
    for name in ("From", "To", "Cc", "Date", "Subject"):
        value = headers.get(name)
        if value:
            parts.append(f"{name}: {value}")
    texts = []
    for p in mime.body_parts(root)[:5]:
        decoded = mime.decode_text(p.decoded(), p.charset)
        texts.append(html_to_text(decoded) if p.subtype == "html" else plain_text(decoded))
    return "\n".join(parts) + "\n\n" + "\n\n".join(texts)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
