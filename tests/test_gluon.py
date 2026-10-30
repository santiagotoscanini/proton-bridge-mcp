"""End to end against a real gluon (the IMAP engine inside Bridge), laid out
like Bridge (tests/gluon/demo.go). Needs PROTON_MCP_GLUON = the demo binary;
the nix build always provides it.

What gluon's demo does NOT reproduce, and the fake server covers instead:
Bridge rebuilds every message (Q-encoded headers, quoted-printable text
parts, X-Pm-* headers, synthesized Message-IDs), Proton's folder/label
semantics behind COPY/MOVE/EXPUNGE (the demo's connector just moves rows),
"All Mail" containing everything, and the outage behaviours (listener
closed, sockets dropped without BYE)."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import Cert, CredsServer, creds_doc, fixture
from imapclient import IMAPClient

from proton_mcp import ids, mime
from proton_mcp.credentials import EndpointSource, ssl_context
from proton_mcp.imapconn import Bridge
from proton_mcp.messages import DateCache
from proton_mcp.service import Mail
from proton_mcp.uidplus import find_code

GLUON = os.environ.get("PROTON_MCP_GLUON")
pytestmark = pytest.mark.gluon
ADDRS = ["user1@example.com", "alias1@example.com"]
DAY = 86400
T0 = 1_788_000_000  # 2026-08-29

if not GLUON:
    if os.environ.get("PROTON_MCP_REQUIRE_GLUON"):
        raise RuntimeError("PROTON_MCP_REQUIRE_GLUON is set but PROTON_MCP_GLUON is not")
    pytest.skip("PROTON_MCP_GLUON is not set", allow_module_level=True)


@dataclass
class Gluon:
    proc: subprocess.Popen
    port: int
    cert: Cert

    def raw(self) -> IMAPClient:
        """An unguarded client for seeding and for checking state."""
        conn = IMAPClient("127.0.0.1", self.port, ssl=True, ssl_context=ssl_context(self.cert.pem), timeout=30)
        conn.login("user1@example.com", "pass")
        return conn


def start_gluon(tmp: Path, cert: Cert) -> Gluon:
    env = {
        **os.environ,
        "GLUON_DIR": str(tmp),
        "GLUON_TLS_CERT": str(cert.cert),
        "GLUON_TLS_KEY": str(cert.key),
        "GLUON_HOST": "127.0.0.1:0",
        "GLUON_LOG_LEVEL": "error",
    }
    proc = subprocess.Popen([GLUON], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    line = proc.stdout.readline()
    assert line.startswith("listening on "), line
    return Gluon(proc, int(line.rsplit(":", 1)[1]), cert)


def when(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, UTC)


def append(conn: IMAPClient, mailbox: str, raw: bytes, epoch: int, flags: tuple[str, ...] = (), internal_id: str = "") -> int:
    if internal_id:
        raw = f"X-Pm-Internal-Id: {internal_id}\r\n".encode() + raw
    res = conn.append(mailbox, raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"), flags=flags, msg_time=when(epoch))

    code = find_code("APPENDUID", conn._imap.untagged_responses.pop("APPENDUID", []), [res])
    assert code is not None
    return code.dest[0]


def unseen(conn: IMAPClient, mailbox: str) -> int:
    return conn.folder_status(mailbox, ["UNSEEN"])[b"UNSEEN"]


SEED = [
    # (mailbox, fixture, day offset, flags, internal id)
    ("INBOX", "qp-utf8.eml", 30, (), "g-qp=="),
    ("INBOX", "html-only.eml", 29, (), "g-html=="),
    ("INBOX", "related-cid.eml", 28, (), "g-rel=="),
    ("INBOX", "invite-request.eml", 27, (), "g-inv=="),
    ("INBOX", "reply-thread.eml", 26, ("\\Seen",), "g-r3=="),
    ("Archive", "rfc2231-filename.eml", 25, ("\\Seen",), "g-2231=="),
    ("Archive", "nested-rfc822.eml", 24, (), "g-nest=="),
    ("INBOX", "multipart-mixed-gluon.eml", 23, ("\\Flagged",), "g-mm=="),
    ("Sent", "rfc2047-split.eml", 22, ("\\Seen",), "g-split=="),
    ("INBOX", "latin1.eml", 21, (), "g-l1=="),
    ("INBOX", "bridge-shapes.eml", 20, (), "g-bridge=="),
    ("INBOX", "pgp-attachment.eml", 19, (), "g-pgp=="),
    ("INBOX", "undecryptable-body.eml", 18, (), "g-undec=="),
    ("INBOX", "zero-width.eml", 17, (), "g-zw=="),
    ("Spam", "data-uri.eml", 16, (), "g-spam=="),
]


@pytest.fixture(scope="module")
def gluon(tmp_path_factory: pytest.TempPathFactory, certs: dict) -> Iterator[Gluon]:
    g = start_gluon(tmp_path_factory.mktemp("gluon"), certs["bridge"])
    conn = g.raw()
    for name in ("Folders/Receipts", "Folders/Projects", "Labels/Work", "Labels/Family"):
        conn.create_folder(name)
    for mailbox, name, day, flags, iid in SEED:
        append(conn, mailbox, fixture(name), T0 + day * DAY, flags, iid)
    # The thread's ancestors, in other folders.
    append(
        conn,
        "Archive",
        b"From: a@example.org\r\nTo: user1@example.com\r\nSubject: Budget 2027\r\nDate: Sat, 24 Oct 2026 08:00:00 +0000\r\nMessage-ID: <reply-1@example.org>\r\n\r\nroot\r\n",
        T0 + 10 * DAY,
        (),
        "g-r1==",
    )
    append(
        conn,
        "Sent",
        b"From: user1@example.com\r\nTo: pat@example.org\r\nSubject: Re: Budget 2027\r\nDate: Sun, 25 Oct 2026 08:00:00 +0000\r\nMessage-ID: <reply-2@example.com>\r\nIn-Reply-To: <reply-1@example.org>\r\n\r\nmine\r\n",
        T0 + 11 * DAY,
        ("\\Seen",),
        "g-r2==",
    )
    conn.logout()
    yield g
    g.proc.terminate()
    g.proc.wait(10)


@pytest.fixture()
def mail(gluon: Gluon, creds_server: CredsServer) -> Iterator[Mail]:
    doc = creds_doc(gluon.cert, gluon.port, 1, password="pass")
    doc["accounts"][0]["addresses"] = list(ADDRS)
    creds_server.doc = doc
    bridge = Bridge(EndpointSource(f"http://127.0.0.1:{creds_server.server_address[1]}/v1/account"), sleep=lambda s: None)
    yield Mail(bridge, DateCache())
    bridge.close()


def subject_id(mail: Mail, text: str, **extra: object) -> str:
    res = mail.search({"subject": text, **extra})["results"]
    assert res, text
    return res[0]["id"]


def test_mailbox_layout_is_bridges(mail: Mail) -> None:
    roles = {m["name"]: m["role"] for m in mail.list_mailboxes()["mailboxes"]}
    assert roles["INBOX"] == "inbox" and roles["Drafts"] == "drafts" and roles["Spam"] == "spam"
    assert roles["All Mail"] == "all" and roles["Starred"] == "starred" and roles["Archive"] == "archive"
    assert roles["Folders/Receipts"] == "folder" and roles["Labels/Work"] == "label"
    assert "Folders" not in roles and "Labels" not in roles


def test_gluon_search_is_raw_bytes_so_we_verify_client_side(gluon: Gluon, mail: Mail) -> None:
    conn = gluon.raw()
    conn.select_folder("INBOX", readonly=True)
    # The quirk, on the real engine: a QP soft break and an encoded subject defeat SEARCH.
    assert conn.search(["BODY", "presupuesto actualizado"]) == []
    assert conn.search(["SUBJECT", "Reunion"]) == []
    assert conn.search(["SUBJECT", "Reuni"]) != []  # only raw ASCII fragments match
    conn.logout()
    assert [r["untrusted"]["subject"] for r in mail.search({"text": "presupuesto actualizado"})["results"]] == [
        "Reunión del martes"
    ]
    assert len(mail.search({"subject": "reunion"})["results"]) == 1
    assert len(mail.search({"text": "crème"})["results"]) == 1
    assert mail.search({"text": "attacker"})["results"] == []  # hidden HTML is not text


def test_search_order_scope_and_filters(mail: Mail) -> None:
    out = mail.search({"limit": 50})
    dates = [r["date"] for r in out["results"]]
    assert dates == sorted(dates, reverse=True)
    assert "Spam" not in {r["mailbox"] for r in out["results"]}
    assert {r["mailbox"] for r in out["results"]} == {"INBOX", "Archive", "Sent"}
    assert len(mail.search({"include_spam_trash": True, "limit": 50})["results"]) == len(out["results"]) + 1
    assert [r["untrusted"]["subject"] for r in mail.search({"starred": True})["results"]] == ["Simple test mail"]
    assert {r["mailbox"] for r in mail.search({"unread": False, "limit": 50})["results"]} >= {"Sent", "Archive"}
    first = mail.search({"limit": 4})
    second = mail.search({"limit": 4, "cursor": first["next_cursor"]})
    assert not {r["id"] for r in first["results"]} & {r["id"] for r in second["results"]}
    assert first["results"][-1]["date"] >= second["results"][0]["date"]


@pytest.mark.parametrize("name", [s[1] for s in SEED])
@pytest.mark.parametrize("path", ["whole", "parts"])
def test_get_message_matches_local_decoding(mail: Mail, name: str, path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_mime_corpus import loaded

    from proton_mcp import service

    if path == "parts":
        monkeypatch.setattr(service, "FULL_FETCH", 0)  # force BODYSTRUCTURE + BODY.PEEK[part]
    headers, _ = mime.parse_message(fixture(name))
    subject = headers.get("Subject") or ""
    hits = [r for r in mail.search({"include_spam_trash": True, "limit": 50})["results"] if r["untrusted"]["subject"] == subject]
    assert hits, subject
    msg = mail.get_message(hits[0]["id"])
    local_text, undecryptable, _ = loaded(fixture(name).replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")).text()
    assert msg["untrusted"]["text"] == local_text[: len(msg["untrusted"]["text"])]
    assert msg["undecryptable"] is undecryptable
    local_atts = [(a["part"], a["content_type"]) for a in service._attachment_rows(loaded(fixture(name)).root)]
    assert [(a["part"], a["content_type"]) for a in msg["attachments"]] == local_atts


def test_bodystructure_numbering_matches_gluon(gluon: Gluon) -> None:
    conn = gluon.raw()
    for box in ("INBOX", "Archive", "Sent"):
        conn.select_folder(box, readonly=True)
        fetched = conn.fetch(conn.search(["ALL"]), ["BODYSTRUCTURE", "BODY.PEEK[]"])
        for data in fetched.values():
            server = mime.from_bodystructure(data[b"BODYSTRUCTURE"])
            _, local = mime.parse_message(data[b"BODY[]"])
            leaves = lambda p: [(x.section, x.content_type) for x in p.walk() if not x.is_multipart]  # noqa: E731
            assert leaves(local) == leaves(server)
    conn.logout()


def test_attachments_and_invite(mail: Mail) -> None:
    trip = subject_id(mail, "trip")
    meta, payloads = mail.get_attachment(trip, "2")
    assert meta["delivered_as"] == "pdf" and payloads[0]["data"].startswith(b"%PDF")
    meta, payloads = mail.get_attachment(trip, "1.2")
    assert meta["delivered_as"] == "image" and payloads[0]["data"].startswith(b"\x89PNG")
    csv = subject_id(mail, "encoded names")
    meta, _ = mail.get_attachment(csv, "3")
    assert meta["untrusted"]["filename"] == "informe de gastos €.csv" and "coffee,3.50" in meta["untrusted"]["text"]
    inv = mail.get_message(subject_id(mail, "Planning"))["invite"]
    assert inv["method"] == "REQUEST" and inv["invited_address"] == "me@example.com" and inv["answerable_here"] is False


def test_thread_across_folders(mail: Mail) -> None:
    th = mail.get_thread(subject_id(mail, "Budget", mailbox="inbox"))
    assert [m["untrusted"]["snippet"] for m in th["messages"]][:2] == ["root", "mine"]
    assert len(th["messages"]) == 3 and not th["heuristic"]
    assert [m["mailbox"] for m in th["messages"]] == ["Archive", "Sent", "INBOX"]


def test_reading_everything_sets_no_seen_flag(gluon: Gluon, mail: Mail) -> None:
    conn = gluon.raw()
    boxes = ["INBOX", "Archive", "Sent", "Spam"]
    before = {b: unseen(conn, b) for b in boxes}
    for r in mail.search({"include_spam_trash": True, "limit": 50})["results"]:
        msg = mail.get_message(r["id"])
        for a in msg["attachments"][:2]:
            mail.get_attachment(r["id"], a["part"])
        mail.get_thread(r["id"])
    assert {b: unseen(conn, b) for b in boxes} == before
    conn.logout()


def test_organize_on_gluon(gluon: Gluon, mail: Mail) -> None:
    conn = gluon.raw()
    mid = subject_id(mail, "Latin-1")
    out = mail.mark([mid], read=True, starred=True)
    assert out["results"][0]["ok"] and set(out["results"][0]["flags"]) >= {"read", "starred"}
    mail.mark([mid], read=False, starred=False)
    moved = mail.move([mid], "archive")["results"][0]
    assert moved["ok"] and ids.decode(moved["id"]).mailbox == "Archive"
    assert mail.get_message(moved["id"])["untrusted"]["headers"]["subject"] == "Latin-1 body"
    back = mail.move([moved["id"]], "inbox")["results"][0]
    assert back["ok"]
    labeled = mail.label([back["id"]], add=["Work"])
    assert labeled["results"]["Labels/Work"][0]["ok"]
    conn.select_folder("Labels/Work", readonly=True)
    assert conn.search(["ALL"]) != []
    view = subject_id(mail, "Latin-1", mailbox="Labels/Work")
    copied = mail.move([view], "Folders/Receipts")["results"][0]  # from a view: COPY
    assert copied["ok"]
    removed = mail.label([back["id"]], remove=["Work"])
    assert removed["results"]["Labels/Work"][0]["ok"]
    conn.select_folder("Labels/Work", readonly=True)
    assert conn.search(["ALL"]) == []
    conn.select_folder("INBOX", readonly=True)
    # Folders are exclusive (gluon's connector, like Proton): the copy from the
    # label view moved it out of INBOX into the folder; the label is gone.
    conn.select_folder("Folders/Receipts", readonly=True)
    assert conn.search(["HEADER", "Message-ID", "latin1-1@example.com"]) != []
    conn.select_folder("INBOX", readonly=True)
    assert conn.search(["HEADER", "Message-ID", "latin1-1@example.com"]) == []


def test_structure_on_gluon(mail: Mail) -> None:
    assert mail.folders("create", "Clients")["ok"]
    assert mail.folders("create", "Clients/2026")["ok"]
    assert mail.folders("rename", "Clients/2026", "Clients/2027")["ok"]
    assert mail.folders("delete", "Clients/2027")["ok"]
    assert mail.folders("delete", "Clients")["ok"]
    assert mail.labels("create", "Urgent")["ok"]
    assert mail.labels("rename", "Urgent", "Soon")["ok"]
    assert mail.labels("delete", "Soon")["ok"]
    names = {m["name"] for m in mail.list_mailboxes()["mailboxes"]}
    assert not {n for n in names if n.startswith(("Folders/Clients", "Labels/Urgent", "Labels/Soon"))}


def test_drafts_on_gluon(gluon: Gluon, mail: Mail) -> None:
    conn = gluon.raw()
    d1 = mail.draft_email(
        {"to": ["Rae <rae@example.com>"], "subject": "Plan", "body": "Primer borrador ñ", "from": "alias1@example.com"}
    )
    assert d1["draft_id"] and ids.decode(d1["draft_id"]).mailbox == "Drafts"
    conn.select_folder("Drafts", readonly=True)
    flags = conn.get_flags([ids.decode(d1["draft_id"]).uid])
    assert b"\\Draft" in next(iter(flags.values()))
    d2 = mail.update_draft({"id": d1["draft_id"], "body": "Segundo borrador", "to": ["rae@example.com", "sam@example.org"]})
    assert d2["old_version_removed"] and d2["to"] == ["rae@example.com", "sam@example.org"] and d2["from"] == "alias1@example.com"
    text = mail.get_message(d2["draft_id"])["untrusted"]["text"]
    assert text.startswith("Segundo borrador")
    reply = mail.draft_reply(subject_id(mail, "Budget", mailbox="inbox"), "Agreed", reply_all=True)
    assert reply["to"] == ["pat@example.org"] and reply["subject"] == "Re: Budget 2027"
    fwd = mail.draft_forward(subject_id(mail, "trip"), ["sam@example.org"], "FYI")
    assert fwd["attachments"] == 2
    for draft in (d2, reply, fwd):
        assert mail.discard_draft(draft["draft_id"])["ok"]
    conn.select_folder("Drafts", readonly=True)
    assert conn.search(["ALL"]) == []
    conn.logout()


def test_uidvalidity_bump_on_gluon(gluon: Gluon, mail: Mail) -> None:
    mid = subject_id(mail, "Factura")
    before = ids.decode(mid)
    gluon.proc.send_signal(signal.SIGUSR1)
    assert gluon.proc.stdout is not None and gluon.proc.stdout.readline().strip() == "uidvalidity bumped"
    deadline = time.time() + 10
    while time.time() < deadline:
        conn = gluon.raw()
        uv = conn.select_folder("INBOX", readonly=True)[b"UIDVALIDITY"]
        conn.logout()
        if uv != before.uidvalidity:
            break
        time.sleep(0.2)
    else:
        pytest.skip("this gluon did not bump UIDVALIDITY")
    mail.bridge.close()  # a resync drops clients
    msg = mail.get_message(mid)
    assert msg["untrusted"]["headers"]["subject"].startswith("Factura")
    assert ids.decode(msg["id"]).uidvalidity != before.uidvalidity
