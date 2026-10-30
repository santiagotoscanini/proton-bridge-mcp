"""The tools against the scripted fake Bridge: what each sends on the wire,
and how it behaves under Bridge's semantics and faults."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from conftest import ADDRESSES, Env, fixture

from proton_mcp import ids, imapconn
from proton_mcp.errors import BridgeUnavailable, InvalidArgument, NotFound, Refused, StaleId

DAY = 86400
T0 = int(datetime(2026, 10, 1, 12, 0, tzinfo=UTC).timestamp())

READ_COMMANDS = {"CAPABILITY", "LOGIN", "NOOP", "LIST", "STATUS", "EXAMINE", "UNSELECT", "LOGOUT"}
WRITE_WORDS = ("SELECT", "STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "CREATE", "DELETE", "RENAME", "CLOSE")


def seed_basic(env: Env) -> dict[str, object]:
    """Inbox newest first (Bridge's UID order after sync), a label view and All Mail."""
    s = env.store
    msgs = {}
    # Seeded newest first so UIDs run newest -> oldest, as after Bridge's sync.
    msgs["bridge"] = s.add(
        "INBOX",
        fixture("bridge-shapes.eml"),
        T0 + 9 * DAY,
        also_in=("All Mail", "Labels/Work") if "Labels/Work" in s.boxes else ("All Mail",),
    )
    msgs["qp"] = s.add("INBOX", fixture("qp-utf8.eml"), T0 + 8 * DAY, flags=("\\Seen",), also_in=("All Mail",))
    msgs["html"] = s.add("INBOX", fixture("html-only.eml"), T0 + 7 * DAY, also_in=("All Mail",))
    msgs["related"] = s.add("Archive", fixture("related-cid.eml"), T0 + 6 * DAY, also_in=("All Mail",))
    msgs["invite"] = s.add("INBOX", fixture("invite-request.eml"), T0 + 5 * DAY, also_in=("All Mail",))
    msgs["plain"] = s.add(
        "INBOX", fixture("plain-ascii.eml"), T0 + 4 * DAY, flags=("\\Seen", "\\Flagged"), also_in=("All Mail", "Starred")
    )
    msgs["split"] = s.add("Sent", fixture("rfc2047-split.eml"), T0 + 3 * DAY, flags=("\\Seen",), also_in=("All Mail",))
    msgs["spam"] = s.add("Spam", fixture("data-uri.eml"), T0 + 2 * DAY, also_in=("All Mail",))
    msgs["reply"] = s.add("INBOX", fixture("reply-thread.eml"), T0 + 1 * DAY, flags=("\\Seen",), also_in=("All Mail",))
    return msgs


@pytest.fixture()
def seeded(env: Env) -> dict[str, object]:
    env.store.create("Labels/Work")
    env.store.create("Folders/Receipts")
    msgs = seed_basic(env)
    env.imap.clear()
    return msgs


def commands(env: Env) -> list[str]:
    return env.imap.sent()


def assert_read_only(env: Env) -> None:
    sent = commands(env)
    assert sent, "nothing was sent"
    for line in sent:
        word = line.split(" ", 1)[0].upper()
        if word == "UID":
            sub = line.split()[1].upper()
            assert sub in ("SEARCH", "FETCH"), line
        else:
            assert word in READ_COMMANDS, line
        assert not word.startswith(WRITE_WORDS), line
    for line in sent:
        if line.upper().startswith("UID FETCH"):
            assert not re.search(r"(?<!\.)BODY\[", line.upper().replace("BODY.PEEK[", "")), line
            assert "RFC822 " not in line.upper() + " " and "RFC822.TEXT" not in line.upper(), line


def find(results: list[dict], subject_part: str) -> dict:
    for r in results:
        if subject_part in r["untrusted"]["subject"]:
            return r
    raise AssertionError(f"no result with {subject_part!r}: {[r['untrusted']['subject'] for r in results]}")


# ── reads ────────────────────────────────────────────────────────────────


def test_list_mailboxes_roles_counts_and_noselect(env: Env, seeded: dict) -> None:
    out = env.mail.list_mailboxes()
    by = {m["name"]: m for m in out["mailboxes"]}
    assert out["addresses"] == ADDRESSES
    assert "Folders" not in by and "Labels" not in by  # \Noselect parents skipped
    assert by["INBOX"]["role"] == "inbox" and by["All Mail"]["role"] == "all" and by["Starred"]["role"] == "starred"
    assert by["Spam"]["role"] == "spam" and by["Labels/Work"]["role"] == "label" and by["Folders/Receipts"]["role"] == "folder"
    assert by["INBOX"]["messages"] == 6 and by["INBOX"]["unseen"] == 3
    assert_read_only(env)


def test_search_default_scope_newest_first_dedup_and_read_only(env: Env, seeded: dict) -> None:
    out = env.mail.search({"limit": 50})
    subjects = [r["untrusted"]["subject"] for r in out["results"]]
    dates = [r["date"] for r in out["results"]]
    assert dates == sorted(dates, reverse=True)  # by INTERNALDATE, though UIDs ran newest->oldest
    assert len(subjects) == 8  # spam left out, All Mail/Starred/label copies not repeated
    assert not any("Inline data" in s for s in subjects)
    assert "Archive" in {r["mailbox"] for r in out["results"]} and "Sent" in {r["mailbox"] for r in out["results"]}
    assert out["partial"] is False and out["next_cursor"] is None
    assert_read_only(env)
    # No text criterion: no SEARCH key that makes gluon decrypt every message.
    for line in commands(env):
        if line.upper().startswith("UID SEARCH"):
            assert not re.search(r"\b(FROM|TO|SUBJECT|BODY|TEXT|HEADER)\b", line.upper()), line


def test_search_results_carry_ids_snippets_and_untrusted_envelope(env: Env, seeded: dict) -> None:
    out = env.mail.search({"from": "José"})
    assert len(out["results"]) == 1
    r = out["results"][0]
    assert r["untrusted"]["from"][0] == {"name": "José Ejemplo", "address": "jose@example.com"}
    assert r["untrusted"]["subject"] == "Reunión del martes"
    assert "presupuesto actualizado" in r["untrusted"]["snippet"]  # QP soft break decoded
    assert set(r) == {"id", "date", "mailbox", "flags", "has_attachments", "size", "untrusted"}
    ref = ids.decode(r["id"])
    assert ref.mailbox == "INBOX" and ref.uidvalidity == env.store.boxes["INBOX"].uidvalidity


def test_search_text_is_verified_on_decoded_bodies(env: Env, seeded: dict) -> None:
    # "presupuesto" is split by a QP soft line break in the raw bytes; raw SEARCH BODY would miss it.
    assert [r["untrusted"]["subject"] for r in env.mail.search({"text": "presupuesto actualizado"})["results"]] == [
        "Reunión del martes"
    ]
    # accent-insensitive, and a phrase across an encoded subject
    assert len(env.mail.search({"text": "reunion"})["results"]) == 1
    assert len(env.mail.search({"subject": "celebration seminar été"})["results"]) == 1
    assert len(env.mail.search({"text": '"seminar — ete"'})["results"]) == 1
    # HTML text is matched after stripping, hidden text is not
    assert len(env.mail.search({"text": "crème"})["results"]) == 1
    assert env.mail.search({"text": "attacker"})["results"] == []
    assert_read_only(env)


def test_search_filters(env: Env, seeded: dict) -> None:
    unread = env.mail.search({"unread": True})["results"]
    assert {r["untrusted"]["subject"] for r in unread} >= {"Weekly digest — issue 12"}
    assert all("read" not in r["flags"] for r in unread)
    starred = env.mail.search({"starred": True})["results"]
    assert [r["untrusted"]["subject"] for r in starred] == ["Lunch on Friday"]
    att = env.mail.search({"has_attachment": True})["results"]
    assert sorted(r["untrusted"]["subject"][:8] for r in att) == ["Invitati", "Photo fr"]
    since = env.mail.search({"since": "2026-10-06", "before": "2026-10-09"})["results"]
    assert len(since) == 3
    assert env.mail.search({"to": "quinn"})["results"][0]["untrusted"]["subject"] == "Re: Budget 2027"
    assert env.mail.search({"cc": "rae@example.com"})["results"][0]["untrusted"]["subject"] == "Re: Budget 2027"
    assert len(env.mail.search({"include_spam_trash": True})["results"]) == 9
    assert [r["mailbox"] for r in env.mail.search({"mailbox": "spam"})["results"]] == ["Spam"]
    assert len(env.mail.search({"mailbox": "all"})["results"]) == 9
    assert len(env.mail.search({"mailbox": "Labels/Work"})["results"]) == 1


def test_search_cursor_pages_without_gaps_or_repeats(env: Env, seeded: dict) -> None:
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        out = env.mail.search({"limit": 3, **({"cursor": cursor} if cursor else {})})
        seen.extend(r["untrusted"]["subject"] for r in out["results"])
        pages += 1
        cursor = out["next_cursor"]
        if not cursor:
            break
    assert pages == 3 and len(seen) == len(set(seen)) == 8
    with pytest.raises(InvalidArgument):
        env.mail.search({"limit": 3, "unread": True, "cursor": env.mail.search({"limit": 3})["next_cursor"]})
    with pytest.raises(InvalidArgument):
        env.mail.search({"cursor": "garbage"})


def test_search_budget_returns_partial_with_resumable_cursor(env: Env, seeded: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    from proton_mcp import search

    monkeypatch.setattr(search, "BATCH", 2)
    monkeypatch.setattr(search, "MAX_ENVELOPES", 2)
    out = env.mail.search({"text": "zzz-not-there", "limit": 5})
    assert out["partial"] is True and out["next_cursor"] and out["results"] == []
    total = out["examined"]
    while out["next_cursor"]:
        out = env.mail.search({"text": "zzz-not-there", "limit": 5, "cursor": out["next_cursor"]})
        total += out["examined"]
    assert total == 8


def test_get_message_full(env: Env, seeded: dict) -> None:
    r = find(env.mail.search({"subject": "Factura"})["results"], "Factura")
    msg = env.mail.get_message(r["id"])
    u = msg["untrusted"]
    assert u["headers"]["subject"] == "Factura nº 2026-118"
    assert u["headers"]["reply_to"] == [{"name": "", "address": "replies@example.org"}]
    assert msg["delivered_to"] == "me.alias@example.org"
    assert "Vence el 15 de noviembre" in u["text"]
    assert u["security"]["X-Pm-Spamscore"] == "0" and "dmarc=pass" in u["security"]["Authentication-Results"]
    assert "X-Pm-Internal-Id" not in u["security"] and "X-Pm-Gluon-Id" not in u["security"]
    assert u["headers"]["list_unsubscribe"].startswith("<mailto:unsubscribe@example.org>")
    assert ids.decode(msg["id"]).internal_id == "bridgeInternal123=="
    assert msg["flags"] == [] and msg["undecryptable"] is False
    assert_read_only(env)
    # Reading did not mark it read.
    assert "\\Seen" not in env.store.flags("INBOX", seeded["bridge"])


def test_get_message_paging(env: Env, seeded: dict) -> None:
    r = find(env.mail.search({"subject": "Reunión"})["results"], "Reunión")
    first = env.mail.get_message(r["id"], max_chars=40)
    assert first["truncated"] and first["next_offset"] == 40 and len(first["untrusted"]["text"]) == 40
    rest = env.mail.get_message(r["id"], max_chars=100000, offset=40)
    assert not rest["truncated"] and rest["next_offset"] is None
    assert first["untrusted"]["text"] + rest["untrusted"]["text"] == env.mail.get_message(r["id"])["untrusted"]["text"]


def test_get_message_large_fetches_only_header_and_text_part(env: Env, seeded: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    from proton_mcp import service

    monkeypatch.setattr(service, "FULL_FETCH", 100)
    r = find(env.mail.search({"subject": "trip"})["results"], "trip")
    env.imap.clear()
    msg = env.mail.get_message(r["id"])
    assert "Itinerary attached" in msg["untrusted"]["text"]
    fetches = [c for c in commands(env) if c.upper().startswith("UID FETCH")]
    assert all("BODY.PEEK[]" not in f for f in fetches)
    assert any("BODY.PEEK[1.1]" in f for f in fetches)  # the HTML part inside multipart/related
    assert [a["untrusted"]["filename"] for a in msg["attachments"]] == ["itinerary.pdf"]
    assert_read_only(env)


def test_get_message_invite(env: Env, seeded: dict) -> None:
    r = find(env.mail.search({"subject": "Planning"})["results"], "Planning")
    inv = env.mail.get_message(r["id"])["invite"]
    assert inv["method"] == "REQUEST" and inv["answerable_here"] is True
    assert inv["invited_address"] == "me@example.com" and inv["your_status"] == "NEEDS-ACTION"
    assert inv["untrusted"]["summary"] == "Planning session"
    assert inv["untrusted"]["organizer"] == {"name": "Olivia Organizer", "address": "organizer@example.org"}
    assert {a["address"] for a in inv["untrusted"]["attendees"]} >= {"me@example.com", "colleague@example.org"}


def test_get_thread_links_ancestors_and_descendants(env: Env) -> None:
    s = env.store
    root = b"From: a@example.org\r\nTo: me@example.com\r\nSubject: Budget 2027\r\nMessage-ID: <reply-1@example.org>\r\nDate: Mon, 26 Oct 2026 08:00:00 +0000\r\n\r\nroot\r\n"
    mine = b"From: me@example.com\r\nTo: a@example.org\r\nSubject: Re: Budget 2027\r\nMessage-ID: <reply-2@example.com>\r\nIn-Reply-To: <reply-1@example.org>\r\nReferences: <reply-1@example.org>\r\nDate: Tue, 27 Oct 2026 08:00:00 +0000\r\n\r\nmine\r\n"
    later = b"From: z@example.org\r\nTo: me@example.com\r\nSubject: Re: Budget 2027\r\nMessage-ID: <reply-4@example.org>\r\nReferences: <reply-1@example.org> <reply-3@example.org> <x@protonmail.internalid>\r\nDate: Fri, 30 Oct 2026 08:00:00 +0000\r\n\r\nlater\r\n"
    unrelated = b"From: b@example.org\r\nTo: me@example.com\r\nSubject: Something else\r\nMessage-ID: <other@example.org>\r\nDate: Thu, 29 Oct 2026 08:00:00 +0000\r\n\r\nx\r\n"
    s.add("INBOX", later, T0 + 29 * DAY)
    s.add("INBOX", fixture("reply-thread.eml"), T0 + 27 * DAY)
    s.add("Sent", mine, T0 + 26 * DAY, also_in=("All Mail",))
    s.add("Archive", root, T0 + 25 * DAY)
    s.add("INBOX", unrelated, T0 + 28 * DAY)
    env.imap.clear()
    hit = env.mail.search({"subject": "Budget", "mailbox": "Sent"})["results"][0]
    th = env.mail.get_thread(hit["id"])
    bodies = [m["untrusted"]["snippet"] for m in th["messages"]]
    assert bodies[0] == "root" and bodies[1] == "mine" and bodies[-1] == "later"
    assert len(th["messages"]) == 4 and th["heuristic"] is False
    assert_read_only(env)
    for line in commands(env):
        assert "HEADER " not in line.upper().split("FETCH")[0], line  # no HEADER search


def test_get_thread_heuristic_when_nothing_links(env: Env) -> None:
    a = b"From: a@example.org\r\nTo: me@example.com\r\nSubject: Fiesta\r\nMessage-ID: <h1@example.org>\r\nDate: Mon, 26 Oct 2026 08:00:00 +0000\r\n\r\none\r\n"
    b = b"From: me@example.com\r\nTo: a@example.org\r\nSubject: RE: Fiesta\r\nMessage-ID: <h2@example.com>\r\nDate: Tue, 27 Oct 2026 08:00:00 +0000\r\n\r\ntwo\r\n"
    env.store.add("INBOX", a, T0 + 25 * DAY)
    env.store.add("Sent", b, T0 + 26 * DAY)
    hit = env.mail.search({"subject": "Fiesta", "mailbox": "inbox"})["results"][0]
    th = env.mail.get_thread(hit["id"])
    assert th["heuristic"] is True and len(th["messages"]) == 2


def test_get_attachment_kinds(env: Env) -> None:
    env.store.add("INBOX", fixture("related-cid.eml"), T0)
    env.store.add("INBOX", fixture("attachment-text-disposition.eml"), T0 + DAY)
    env.store.add("INBOX", fixture("rfc2231-filename.eml"), T0 + 2 * DAY)
    trip = env.mail.search({"subject": "trip"})["results"][0]["id"]
    meta, payloads = env.mail.get_attachment(trip, "2")
    assert meta["delivered_as"] == "pdf" and payloads[0]["data"].startswith(b"%PDF")
    meta, payloads = env.mail.get_attachment(trip, "1.2")
    assert meta["delivered_as"] == "image" and payloads[0]["data"].startswith(b"\x89PNG")
    log = env.mail.search({"subject": "Log file"})["results"][0]["id"]
    meta, _ = env.mail.get_attachment(log, "2")
    assert meta["delivered_as"] == "text" and "ERROR something failed" in meta["untrusted"]["text"]
    meta, _ = env.mail.get_attachment(log, "3")
    assert meta["delivered_as"] == "text" and '"ok": true' in meta["untrusted"]["text"]
    names = env.mail.search({"subject": "encoded names"})["results"][0]["id"]
    meta, payloads = env.mail.get_attachment(names, "4")
    assert meta["delivered_as"] == "metadata" and payloads == [] and meta["untrusted"]["filename"] == "présentation.bin"
    with pytest.raises(NotFound):
        env.mail.get_attachment(names, "9")
    with pytest.raises(InvalidArgument):
        env.mail.get_attachment(names, "1; DROP")
    assert_read_only(env)
    for line in commands(env):
        if line.upper().startswith("UID FETCH") and "BODY.PEEK[" in line:
            assert "BODY.PEEK[]" not in line  # only the one part


# ── writes ───────────────────────────────────────────────────────────────


def _id(env: Env, **criteria: object) -> str:
    return env.mail.search(criteria)["results"][0]["id"]


def test_mark_sends_only_seen_and_flagged_stores(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="Weekly digest")
    env.imap.clear()
    out = env.mail.mark([mid], read=True, starred=True)
    assert out["results"][0]["ok"] and set(out["results"][0]["flags"]) >= {"read", "starred"}
    stores = [c for c in commands(env) if c.upper().startswith("UID STORE")]
    assert stores == [s for s in stores if re.search(r"[+-]FLAGS \(\\(Seen|Flagged)\)$", s)] and len(stores) == 2
    assert {c.split()[0] for c in commands(env)} <= {"CAPABILITY", "LOGIN", "SELECT", "UID", "LIST", "UNSELECT", "EXAMINE"}
    assert "\\Seen" in env.store.flags("INBOX", seeded["html"])
    env.mail.mark([mid], read=False)
    assert "\\Seen" not in env.store.flags("INBOX", seeded["html"])


def test_move_uses_uid_move_and_returns_new_ids(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="Weekly digest")
    env.imap.clear()
    out = env.mail.move([mid], "archive")
    r = out["results"][0]
    assert out["to"] == "Archive" and r["ok"]
    new = ids.decode(r["id"])
    assert new.mailbox == "Archive" and new.uidvalidity == env.store.boxes["Archive"].uidvalidity
    assert any(c.upper().startswith("UID MOVE") for c in commands(env))
    assert not any(c.upper().startswith("UID COPY") for c in commands(env))
    assert env.mail.get_message(r["id"])["untrusted"]["headers"]["subject"].startswith("Weekly digest")
    with pytest.raises(InvalidArgument):
        env.mail.move([r["id"]], "Labels/Work")
    with pytest.raises(NotFound):
        env.mail.move([r["id"]], "Folders/Nope")


def test_move_from_a_view_copies_so_labels_survive(env: Env, seeded: dict) -> None:
    mid = _id(env, mailbox="Labels/Work")
    env.imap.clear()
    out = env.mail.move([mid], "Folders/Receipts")
    assert out["results"][0]["ok"]
    assert any(c.upper().startswith("UID COPY") for c in commands(env))
    assert not any(c.upper().startswith("UID MOVE") for c in commands(env))


def test_move_reports_uids_bridge_silently_skipped(env: Env, seeded: dict) -> None:
    good = _id(env, subject="Weekly digest")
    ref = ids.decode(good)
    ghost = ids.MessageRef(ref.mailbox, ref.uidvalidity, 999, ref.date, "").encode()
    out = env.mail.move([good, ghost], "trash")
    ok = {r["ok"] for r in out["results"]}
    assert ok == {True, False}


def test_label_add_and_remove_only_unlabel(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="Lunch")
    env.imap.clear()
    out = env.mail.label([mid], add=["Work"])
    assert out["results"]["Labels/Work"][0]["ok"]
    assert any(re.match(r'UID COPY \d+ "Labels/Work"', c) for c in commands(env))
    env.imap.clear()
    out = env.mail.label([mid], remove=["Labels/Work"])
    assert out["results"]["Labels/Work"][0]["ok"]
    sent = commands(env)
    selects = [c for c in sent if c.upper().startswith("SELECT")]
    assert selects == ['SELECT "Labels/Work"']  # only the label mailbox is ever SELECTed
    assert any(re.match(r"UID STORE \d+ \+FLAGS\.SILENT \(\\Deleted\)$", c) for c in sent)
    assert any(re.match(r"UID EXPUNGE \d+$", c) for c in sent)
    # The message is still in INBOX; only its label copy went.
    assert seeded["plain"] in [e.msg for e in env.store.boxes["INBOX"].entries.values()]
    assert all(box == "Labels/Work" for box, _ in env.imap.expunged)
    with pytest.raises(NotFound):
        env.mail.label([mid], add=["Missing"])


def test_folders_and_labels_structure(env: Env, seeded: dict) -> None:
    env.imap.clear()
    assert env.mail.folders("create", "Projects")["ok"]
    assert env.mail.folders("create", "Folders/Projects/2026")["ok"]
    assert env.mail.folders("rename", "Projects/2026", "Projects/2027")["ok"]
    out = env.mail.folders("delete", "Projects")
    assert out["ok"] and out["also_removed"] == ["Folders/Projects/2027"]
    assert env.mail.labels("create", "Urgent")["ok"]
    assert env.mail.labels("rename", "Urgent", "Later")["ok"]
    assert env.mail.labels("delete", "Labels/Later")["ok"]
    with pytest.raises(InvalidArgument):
        env.mail.labels("create", "Nested/Label")
    with pytest.raises(Refused):
        env.mail.folders("create", "Receipts")  # exists
    for c in commands(env):
        if c.split()[0] in ("CREATE", "DELETE", "RENAME"):
            assert all(arg.startswith(('"Folders/', '"Labels/')) for arg in re.findall(r'"[^"]*"', c)), c


def test_draft_email_appends_to_drafts_only(env: Env, seeded: dict) -> None:
    env.imap.clear()
    out = env.mail.draft_email(
        {"to": ["Rae <rae@example.com>"], "subject": "Hola", "body": "Texto con ñ", "from": "me.alias@example.org"}
    )
    assert out["draft_id"] and out["from"] == "me.alias@example.org" and out["to"] == ["rae@example.com"]
    ((box, uid, literal, flags),) = env.imap.appended
    assert box == "Drafts" and flags == {"\\Draft", "\\Seen"}
    assert b"X-Pm-" not in literal and b"rae@example.com" in literal
    assert [c.split()[0] for c in commands(env) if c.split()[0] in ("APPEND", "SELECT", "STORE", "UID")].count("APPEND") == 1
    with pytest.raises(Refused):
        env.mail.draft_email({"to": ["x@example.com"], "subject": "s", "body": "b", "from": "someone@example.net"})


def test_draft_reply_all_threading_and_from(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="Budget")
    out = env.mail.draft_reply(mid, "Agreed.", reply_all=True)
    assert out["to"] == ["pat@example.org"]
    assert set(out["cc"]) == {"quinn@example.net", "rae@example.com"}  # own addresses dropped
    assert out["subject"] == "Re: Budget 2027" and out["from"] == "me@example.com"
    literal = env.imap.appended[-1][2]
    assert b"In-Reply-To: <reply-3@example.org>" in literal
    assert b"References: <reply-1@example.org> <reply-2@example.com> <reply-3@example.org>" in literal
    assert b"> Numbers look fine to me." in literal.replace(b"=\r\n", b"")


def test_draft_forward_with_attachments(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="trip")
    out = env.mail.draft_forward(mid, ["sam@example.net"], "FYI")
    assert out["attachments"] == 2 and out["subject"] == "Fwd: Photo from the trip"
    literal = env.imap.appended[-1][2]
    assert b'filename="itinerary.pdf"' in literal and b"Forwarded message" in literal


def test_invite_response_draft_and_refusals(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="Planning")
    out = env.mail.draft_invite_response(mid, "tentative", "Might be late")
    assert out["to"] == ["organizer@example.org"] and out["subject"] == "Tentatively accepted: Planning session"
    literal = env.imap.appended[-1][2]
    assert b"text/calendar" in literal and b"method=" in literal.lower()
    env.store.add("INBOX", fixture("invite-other-address.eml"), T0 + 20 * DAY)
    other = _id(env, subject="Offsite")
    with pytest.raises(Refused, match="Google Calendar"):
        env.mail.draft_invite_response(other, "accept")
    env.store.add("INBOX", fixture("invite-cancel.eml"), T0 + 21 * DAY)
    with pytest.raises(Refused, match="CANCEL"):
        env.mail.draft_invite_response(_id(env, subject="Canceled"), "accept")


def test_update_and_discard_draft(env: Env, seeded: dict) -> None:
    first = env.mail.draft_email({"to": ["a@example.com"], "subject": "v1", "body": "first"})
    env.imap.clear()
    second = env.mail.update_draft({"id": first["draft_id"], "body": "second", "cc": ["c@example.com"]})
    assert second["old_version_removed"] and second["draft_id"] != first["draft_id"]
    assert second["subject"] == "v1" and second["to"] == ["a@example.com"] and second["cc"] == ["c@example.com"]
    sent = commands(env)
    assert [c for c in sent if c.startswith("SELECT")] == ['SELECT "Drafts"']
    assert sum(1 for c in sent if c.startswith("APPEND")) == 1
    assert len(env.store.boxes["Drafts"].entries) == 1
    env.imap.clear()
    gone = env.mail.discard_draft(second["draft_id"])
    assert gone["ok"] and not env.store.boxes["Drafts"].entries
    assert [c for c in commands(env) if c.startswith("SELECT")] == ['SELECT "Drafts"']
    # Not a draft, or not in Drafts: refused before any write.
    with pytest.raises(Refused):
        env.mail.discard_draft(_id(env, subject="Lunch"))
    env.store.add("Drafts", fixture("plain-ascii.eml"), T0)  # in Drafts but without \Draft
    with pytest.raises(Refused):
        env.mail.discard_draft(_id(env, mailbox="drafts"))


# ── Bridge's faults ──────────────────────────────────────────────────────


def test_no_with_empty_text_is_a_typed_error(env: Env, seeded: dict) -> None:
    env.imap.fail("UID SEARCH", "no-empty")
    from proton_mcp.errors import ImapError

    with pytest.raises(ImapError, match="no reason given"):
        env.mail.search({})


def test_bare_no_is_bridge_unavailable_after_one_retry(env: Env, seeded: dict) -> None:
    # "TAG NO" without the space imaplib's grammar wants reads as a protocol
    # error: the connection is dropped and the read retried once.
    env.imap.fail("UID SEARCH", "no-bare", count=2)
    with pytest.raises(BridgeUnavailable):
        env.mail.search({})
    env.imap.fail("UID SEARCH", "no-bare", count=1)
    assert env.mail.search({"limit": 2})["results"]


def test_drop_mid_fetch_without_bye_retries_once_on_a_fresh_connection(env: Env, seeded: dict) -> None:
    env.imap.fail("UID FETCH", "drop-mid-fetch")
    out = env.mail.search({"limit": 5})
    assert len(out["results"]) == 5
    sessions = {s for s, _, _ in env.imap.commands}
    assert len(sessions) == 2


def test_listener_refusing_is_bridge_unavailable(env: Env, seeded: dict) -> None:
    env.mail.list_mailboxes()
    env.bridge.close()
    env.imap.refuse()
    with pytest.raises(BridgeUnavailable):
        env.mail.list_mailboxes()


def test_a_write_dropped_on_the_wire_is_not_retried(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="Weekly digest")
    env.imap.fail("UID MOVE", "drop")
    with pytest.raises(BridgeUnavailable) as err:
        env.mail.move([mid], "archive")
    assert err.value.detail.get("outcome") == "unknown"
    assert sum(1 for c in commands(env) if c.startswith("UID MOVE")) == 1


def test_uidvalidity_bump_reresolves_by_internal_id(env: Env, seeded: dict) -> None:
    mid = _id(env, subject="Factura")
    env.store.bump_uidvalidity("INBOX")
    msg = env.mail.get_message(mid)
    assert msg["untrusted"]["headers"]["subject"].startswith("Factura")
    assert ids.decode(msg["id"]).uidvalidity == env.store.boxes["INBOX"].uidvalidity


def test_uidvalidity_bump_without_internal_id_and_ambiguous_is_stale(env: Env) -> None:
    a = b"From: a@example.org\r\nSubject: twin\r\nMessage-ID: <t1@example.org>\r\n\r\none\r\n"
    b = b"From: a@example.org\r\nSubject: twin\r\nMessage-ID: <t2@example.org>\r\n\r\ntwo\r\n"
    env.store.add("INBOX", a, T0)
    env.store.add("INBOX", b, T0)
    mid = _id(env, subject="twin")
    env.store.bump_uidvalidity("INBOX")
    with pytest.raises(StaleId):
        env.mail.get_message(mid)


def test_auth_failure_refetches_credentials(env: Env, seeded: dict) -> None:
    env.mail.list_mailboxes()
    env.bridge.close()
    env.imap.password = "rotated-pass-0002"
    env.creds.doc["accounts"][0]["password"] = "rotated-pass-0002"
    hits = env.creds.hits
    env.mail.list_mailboxes()
    assert env.creds.hits > hits


def test_operation_timeout_drops_the_connection(env: Env, seeded: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(imapconn, "OP_TIMEOUT", 0.5)
    env.imap.hang_seconds = 2.0
    env.imap.fail("LIST", "hang", count=2)
    with pytest.raises(BridgeUnavailable):
        env.mail.list_mailboxes()


def test_pinned_certificate_mismatch_is_refused(env: Env, seeded: dict, certs: dict) -> None:
    env.creds.doc["certificatePem"] = certs["other"].pem
    with pytest.raises(BridgeUnavailable, match="pinned"):
        env.mail.list_mailboxes()
    assert not any(c.startswith("LOGIN") for c in commands(env))


def test_no_connected_account(env: Env) -> None:
    env.creds.doc["accounts"][0]["state"] = "locked"
    with pytest.raises(BridgeUnavailable, match="locked"):
        env.mail.list_mailboxes()


def test_ids_are_validated(env: Env) -> None:
    from proton_mcp.errors import InvalidId

    for bad in ("", "m1.", "m1.!!!", "x" * 3000, 7):
        with pytest.raises(InvalidId):
            env.mail.get_message(bad)  # type: ignore[arg-type]
    with pytest.raises(InvalidArgument):
        env.mail.mark(["m1.x"] * 51, read=True)
