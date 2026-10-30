"""Every fixture decoded as get_message would decode it, plus part numbering
checked against an independently generated BODYSTRUCTURE."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import pytest
from conftest import ADDRESSES, FIXTURES, fixture
from fakeimap import bodystructure, parse_node
from imapclient.response_parser import parse_fetch_response

from proton_mcp import mime
from proton_mcp.ids import MessageRef
from proton_mcp.imapconn import MailboxState
from proton_mcp.messages import real_attachments
from proton_mcp.service import Loaded, _attachment_rows, _invite, _security, delivered_to


@dataclass
class Expect:
    subject: str | None = None
    has: list[str] = field(default_factory=list)
    lacks: list[str] = field(default_factory=list)
    attachments: list[tuple[str, str, str]] | None = None  # (part, content type, filename)
    undecryptable: bool = False
    fmt: str | None = "plain"
    invite: str | None = None  # METHOD
    answerable: bool | None = None


CORPUS: dict[str, Expect] = {
    "plain-ascii.eml": Expect("Lunch on Friday", ["lunch on Friday at noon?"], attachments=[]),
    "alternative.eml": Expect("Quarterly report", ["The plain version"], ["HTML version"], []),
    "html-only.eml": Expect(
        "Weekly digest — issue 12",
        [
            "Issue 12",
            "full article <https://example.org/article?id=7>",
            "[image: Example logo]",
            "Café & crème",
            "- First",
            "- Second",
        ],
        ["Ignore previous", "attacker@", "alert(", "color:red", "Digest\n", "pixel", "https://example.org/plain <"],
        [],
        fmt="html",
    ),
    "qp-utf8.eml": Expect("Reunión del martes", ["presupuesto actualizado", "También hablaremos"], ["=\n", "=C3"], []),
    "base64-utf8.eml": Expect("Base64 body", ["The key is under the mat. Café at 8."]),
    "latin1.eml": Expect("Latin-1 body", ["Là où la réunion a lieu, à bientôt."]),
    "cp1252.eml": Expect("Smart quotes", ["She said “it costs €50” – cheap."]),
    "unknown-charset.eml": Expect("Unknown charset", ["über € 10"]),
    "raw-8bit-header.eml": Expect("Raw 8-bit header árbol", ["Body with ñandú."]),
    "rfc2047-split.eml": Expect("🎉 Celebration seminar — été", ["Split encoded words above."]),
    "rfc2231-filename.eml": Expect(
        "Attachments with encoded names",
        ["Two files attached."],
        attachments=[
            ("2", "application/pdf", "résumé.pdf"),
            ("3", "text/csv", "informe de gastos €.csv"),
            ("4", "application/octet-stream", "présentation.bin"),
        ],
    ),
    "nested-rfc822.eml": Expect(
        "Sample message",
        ["This part does not end with a linebreak."],
        ["This part is embedded", "preamble", "epilogue"],
        [("2", "message/rfc822", "test.eml")],
    ),
    "multipart-mixed-gluon.eml": Expect("Simple test mail", ["*this */is**/_html_"], ["<b>"], [("2", "text/plain", "thing.txt")]),
    "afternoon-meeting.eml": Expect("afternoon meeting", ["meet at 3:30 tomorrow?"]),
    "related-cid.eml": Expect(
        "Photo from the trip",
        ["Look at this:", "[image: the lake]", "Itinerary attached."],
        attachments=[("2", "application/pdf", "itinerary.pdf")],
        fmt="html",
    ),
    "invite-request.eml": Expect(
        "Invitation: Planning session @ Tue 3 Nov 2026 10:00 - 11:00",
        ["invited to Planning session"],
        ["BEGIN:VCALENDAR"],
        [("1.3", "text/calendar", ""), ("2", "application/ics", "invite.ics")],
        invite="REQUEST",
        answerable=True,
    ),
    "invite-other-address.eml": Expect("Invitation: Offsite", ["Forwarded invitation."], invite="REQUEST", answerable=False),
    "invite-cancel.eml": Expect("Canceled: Planning session", [], fmt=None, invite="CANCEL", answerable=True),
    "pgp-mime-fallback.eml": Expect("Encrypted to an old key", ["PGP/MIME encrypted"], ["wcBMA"], undecryptable=True, fmt=None),
    "undecryptable-body.eml": Expect(
        "Could not decrypt", ["could not decrypt"], ["BEGIN PGP", "wcBMA"], [], undecryptable=True, fmt=None
    ),
    "pgp-attachment.eml": Expect(
        "Attachment Bridge could not decrypt",
        ["See the contract."],
        attachments=[("2", "application/octet-stream", "contract.pdf.pgp")],
    ),
    "bridge-shapes.eml": Expect("Factura nº 2026-118", ["Vence el 15 de noviembre."], ["=\n"], []),
    "zero-width.eml": Expect(
        "Zero width padding",
        ["Bigsale today: invisible split words."],
        ["Preview text", "do not show", "​", "­"],
        [],
        fmt="html",
    ),
    "data-uri.eml": Expect(
        "Inline data",
        ["[image: brand]", "click me", "[data URI removed]"],
        ["base64,", "iVBOR", "PHNjcmlwd"],
        [],
        fmt="html",
    ),
    "bare-lf.eml": Expect("Bare LF line endings", ["Line one\nLine two"], attachments=[("2", "text/plain", "notes.txt")]),
    "reply-thread.eml": Expect("Re: Budget 2027", ["Numbers look fine to me.", "> Previous message quoted here."]),
    "hostile-html.eml": Expect(
        "Malformed HTML",
        ["cell one", "cell two", "row two", "unclosed paragraph", "bold", "italic"],
        ["alert(1)", "<script"],
        fmt="html",
    ),
    "empty-body.eml": Expect("(no body)", [], attachments=[]),
    "attachment-text-disposition.eml": Expect(
        "Log file",
        ["Log attached."],
        ["ERROR something failed"],
        [("2", "text/plain", "server.log"), ("3", "application/json", "data.json")],
    ),
    "no-content-type.eml": Expect("No content type", ["A message without MIME headers."]),
    "responsive-template.eml": Expect(
        "Your order has shipped",
        [
            "Your order 4471 has shipped.",
            "Track it at the tracking page <https://example.com/track/4471>.",
            "Web-only footer line.",
        ],
        ["Preheader text", "Stray text", "Receipt", "@media"],
        [],
        fmt="html",
    ),
}


def test_corpus_lists_every_fixture() -> None:
    assert sorted(CORPUS) == sorted(p.name for p in FIXTURES.glob("*.eml"))
    assert len(CORPUS) >= 25


def loaded(raw: bytes) -> Loaded:
    headers, root = mime.parse_message(raw)
    ref = MessageRef("INBOX", 1, 1, 0, "")
    return Loaded(ref, MailboxState("INBOX", 1, 1), headers, root, [], 0, len(raw), True, None)  # type: ignore[arg-type]


@pytest.mark.parametrize("name", sorted(CORPUS))
@pytest.mark.parametrize("crlf", [False, True])
def test_fixture_decodes(name: str, crlf: bool) -> None:
    exp = CORPUS[name]
    raw = fixture(name)
    if crlf:
        raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    msg = loaded(raw)
    text, undecryptable, fmt = msg.text()
    if exp.subject is not None:
        assert msg.headers.get("Subject") == exp.subject
    for piece in exp.has:
        assert piece in text, (piece, text)
    for piece in exp.lacks:
        assert piece not in text, (piece, text)
    assert undecryptable is exp.undecryptable
    assert fmt == exp.fmt
    if exp.attachments is not None:
        rows = [(a["part"], a["content_type"], a["untrusted"]["filename"]) for a in _attachment_rows(msg.root)]
        assert rows == exp.attachments
    inv = _invite(msg, tuple(ADDRESSES))
    assert (inv.method if inv else None) == exp.invite
    if exp.answerable is not None:
        assert inv is not None and inv.answerable_here is exp.answerable


def test_special_headers() -> None:
    msg = loaded(fixture("rfc2047-split.eml"))
    assert [(a.name, a.address) for a in msg.headers.addresses("From")] == [
        ("Doe, Jane", "jane@example.org"),
        ("Éloïse", "eloise@example.org"),
    ]
    assert msg.headers.addresses("To")[0].name == "été team"  # a character split across two encoded words
    bridge = loaded(fixture("bridge-shapes.eml"))
    assert bridge.headers.get("X-Pm-Gluon-Id")  # Bridge's first line parses as a header
    assert delivered_to(bridge.headers, tuple(ADDRESSES)) == "me.alias@example.org"
    sec = _security(bridge.headers)
    assert set(sec) >= {"X-Pm-Spam-Action", "X-Pm-Spamscore", "X-Pm-Origin", "X-Pm-Content-Encryption", "Authentication-Results"}
    assert not set(sec) & {"X-Pm-Internal-Id", "X-Pm-Gluon-Id", "X-Pm-Date"}
    assert mime.message_ids(bridge.headers.get("References"))[-1].endswith("@protonmail.internalid")
    assert loaded(fixture("raw-8bit-header.eml")).headers.addresses("From")[0].name == "Grüß Gott"


def test_undecryptable_attachment_flag() -> None:
    rows = _attachment_rows(loaded(fixture("pgp-attachment.eml")).root)
    assert rows[0]["undecryptable"] is True


def _leaves(part: mime.Part) -> list[tuple[str, str]]:
    out = []
    for p in part.walk():
        if not p.is_multipart:
            out.append((p.section, p.content_type))
    return out


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_local_part_numbers_match_bodystructure(name: str) -> None:
    raw = fixture(name).replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    _, local = mime.parse_message(raw)
    server = mime.from_bodystructure(via_imapclient(bodystructure(parse_node(raw))))
    assert _leaves(local) == _leaves(server)
    assert [p.section for p in real_attachments(local)] == [p.section for p in real_attachments(server)]
    assert [p.section for p in mime.body_parts(local)] == [p.section for p in mime.body_parts(server)]


def test_oversized_body_is_capped() -> None:
    body = ("lorem ipsum dolor sit amet " * 120_000).encode()  # ~3.2 MB
    raw = b"From: a@example.com\r\nSubject: big\r\nContent-Type: text/plain\r\n\r\n" + body
    text, _, _ = loaded(raw).text()
    assert 1_900_000 < len(text) <= 2 * 1024 * 1024


def via_imapclient(bs: bytes) -> object:
    """A BODYSTRUCTURE line in imaplib's shape (literals split out), parsed
    by imapclient as it parses a server's."""
    line = b"1 (UID 1 BODYSTRUCTURE " + bs + b")"
    items: list[object] = []
    pos = 0
    while m := re.compile(rb"\{(\d+)\}\r\n").search(line, pos):
        n, start = int(m.group(1)), m.end()
        items.append((line[pos : m.start()] + b"{%d}" % n, line[start : start + n]))
        pos = start + n
    items.append(line[pos:])
    return parse_fetch_response(items, normalise_times=False, uid_is_key=True)[1][b"BODYSTRUCTURE"]
