"""Unit tests: modified UTF-7, ids, text folding, the IMAP response parser,
header decoding."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from imapclient import imap_utf7
from imapclient.response_parser import parse_fetch_response

from proton_mcp import ids, mime
from proton_mcp.errors import InvalidId
from proton_mcp.imapconn import _entry
from proton_mcp.messages import internal_id
from proton_mcp.textmatch import TextQuery, fold
from proton_mcp.uidplus import expand, find_code

# ── ids ──────────────────────────────────────────────────────────────────

mailbox_names = st.text(st.characters(blacklist_categories=("Cc", "Cs")), min_size=1, max_size=80)


@given(
    mailbox_names,
    st.integers(1, 2**32 - 1),
    st.integers(1, 2**32 - 1),
    st.integers(0, 2**40 - 1),
    st.from_regex(r"[A-Za-z0-9_\-+/=]{0,64}", fullmatch=True),
)
def test_id_round_trip(mailbox: str, uv: int, uid: int, date: int, iid: str) -> None:
    ref = ids.MessageRef(mailbox, uv, uid, date, iid)
    token = ref.encode()
    assert token.startswith("m1.") and ids.decode(token) == ref
    assert all(c.isalnum() or c in "._-" for c in token)


@given(st.text(max_size=200))
@settings(max_examples=300)
def test_id_decode_never_crashes(junk: str) -> None:
    try:
        ids.decode(junk)
    except InvalidId:
        pass


def test_id_rejects_tampering() -> None:
    import base64

    def forge(raw: str) -> str:
        return "m1." + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    good = "1\x1f2\x1f3\x1fabc\x1fINBOX"
    assert ids.decode(forge(good)).mailbox == "INBOX"
    for raw in [
        "0\x1f2\x1f3\x1fabc\x1fINBOX",  # uidvalidity 0
        "1\x1f-2\x1f3\x1fabc\x1fINBOX",
        "1\x1f2\x1f3\x1fa b\x1fINBOX",  # bad internal id
        "1\x1f2\x1f3\x1fabc\x1fIN\r\nBOX",  # control characters
        "1\x1f2\x1f3\x1fabc",  # missing field
        "1\x1f2\x1f3\x1fabc\x1f",  # empty mailbox
    ]:
        with pytest.raises(InvalidId):
            ids.decode(forge(raw))


# ── text folding ─────────────────────────────────────────────────────────


def test_fold() -> None:
    assert fold("  Café​  CRÈME­ ") == "cafe creme"
    assert fold("Łódź Straße Ærø") == "lodz strasse aero"
    assert TextQuery.parse('budget "q3 report"').terms == ("budget", "q3 report")
    q = TextQuery.parse("Reunión martes")
    assert q.matches(fold("la REUNION del Martes")) and not q.matches(fold("reunión lunes"))
    assert q.remaining(fold("reunion")).terms == ("martes",)
    assert not TextQuery.parse("   ")


@given(st.text(max_size=200))
def test_fold_idempotent(text: str) -> None:
    assert fold(fold(text)) == fold(text)


# ── the imapclient adapter ───────────────────────────────────────────────


def fetched(*lines: object) -> dict:
    """Server bytes, in imaplib's shape, through imapclient's own parser."""
    return parse_fetch_response(list(lines), normalise_times=False, uid_is_key=True)


def test_entry_from_imapclient() -> None:
    data = fetched(
        (
            b'1 (UID 7 FLAGS (\\Seen \\Flagged) INTERNALDATE "02-Oct-2026 10:00:00 -0300" RFC822.SIZE 912 '
            b"BODY[HEADER.FIELDS (X-PM-INTERNAL-ID)] {27}",
            b"X-Pm-Internal-Id: abc==\r\n\r\n",
        ),
        (b" BODY[1]<0> {5}", b"hello"),
        b")",
    )
    e = _entry(7, data[7])
    assert e.flags == ["\\Seen", "\\Flagged"] and e.size == 912
    assert e.date == int(datetime(2026, 10, 2, 13, 0, tzinfo=UTC).timestamp())
    assert internal_id(e) == "abc==" and e.section("BODY[1]") == b"hello"


def test_envelope_and_bodystructure_from_imapclient() -> None:
    data = fetched(
        b'5 (UID 3 ENVELOPE ("Mon, 1 Jan 2026 00:00:00 +0000" "=?utf-8?q?Caf=C3=A9?=" (("=?utf-8?q?Jos=C3=A9?=" NIL "jose" "example.com")) '
        b'NIL NIL ((NIL NIL "me" "example.com") (NIL NIL "undisclosed-recipients" NIL) (NIL NIL NIL NIL)) NIL NIL "<p@example.com>" "<m@example.com>") '
        b'BODYSTRUCTURE (("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "QUOTED-PRINTABLE" 120 3 NIL NIL NIL NIL)'
        b'("APPLICATION" "PDF" ("NAME*" "UTF-8\'\'r%C3%A9sum%C3%A9.pdf") NIL NIL "BASE64" 4000 NIL ("ATTACHMENT" ("FILENAME" "=?utf-8?q?r=C3=A9sum=C3=A9.pdf?=")) NIL NIL)'
        b'("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 300 (NIL "inner" NIL NIL NIL NIL NIL NIL NIL NIL) '
        b'(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 20 1 NIL NIL NIL NIL)("TEXT" "HTML" NIL NIL NIL "7BIT" 20 1 NIL NIL NIL NIL) "ALTERNATIVE" NIL NIL NIL NIL) 10 NIL ("ATTACHMENT" NIL) NIL NIL)'
        b' "MIXED" ("BOUNDARY" "b") NIL NIL NIL))'
    )
    e = _entry(3, data[3])
    env = e.envelope
    assert env is not None and mime.decode_header(env.subject) == "Café"
    assert env.from_[0].address == "jose@example.com" and mime.decode_header(env.from_[0].name) == "José"
    assert [a.address for a in env.to] == ["me@example.com"]  # group markers dropped
    assert env.in_reply_to == "<p@example.com>" and env.message_id == "<m@example.com>"
    root = mime.from_bodystructure(e.bodystructure)
    leaves = [(p.section, p.content_type) for p in root.walk() if not p.is_multipart]
    assert leaves == [
        ("1", "text/plain"),
        ("2", "application/pdf"),
        ("3", "message/rfc822"),
        ("3.1", "text/plain"),
        ("3.2", "text/html"),
    ]
    pdf = root.find("2")
    assert pdf is not None and pdf.filename == "résumé.pdf" and pdf.is_attachment and pdf.decoded_size_estimate == 3000


def test_gluons_rfc822_as_multipart_quirk() -> None:
    """gluon renders an encapsulated multipart message as a multipart whose
    subtype is rfc822 (observed on gluon 7e800978ab4a)."""
    data = fetched(
        b'1 (UID 1 BODYSTRUCTURE (("text" "plain" ("charset" "us-ascii") NIL NIL "7BIT" 40 1 NIL NIL NIL NIL)'
        b'(("text" "plain" ("charset" "us-ascii") NIL NIL "7BIT" 36 4 NIL NIL NIL NIL)("text" "plain" ("charset" "us-ascii") NIL NIL "7BIT" 26 1 NIL NIL NIL NIL)'
        b' "rfc822" ("name" "test.eml") ("attachment" ("filename" "test.eml")) NIL NIL) "mixed" ("boundary" "simple boundary") NIL NIL NIL))'
    )
    root = mime.from_bodystructure(_entry(1, data[1]).bodystructure)
    msg = root.find("2")
    assert msg is not None and msg.content_type == "message/rfc822" and msg.filename == "test.eml"
    assert [p.section for p in root.walk() if not p.is_multipart] == ["1", "2", "2.1", "2.2"]
    assert [p.section for p in mime.attachments(root, mime.body_parts(root))] == ["2"]


def test_mailbox_names_through_imapclient() -> None:
    assert imap_utf7.decode(imap_utf7.encode("Folders/Été & co")) == "Folders/Été & co"
    assert imap_utf7.encode("Labels/日本語") == b"Labels/&ZeVnLIqe-"


def test_uidplus_codes() -> None:
    code = find_code("COPYUID", [b"38505 304,319:320 3956:3958"], [])
    assert code and code.mapping() == {304: 3956, 319: 3957, 320: 3958}
    code = find_code("APPENDUID", [], [b"[APPENDUID 38505 3955] APPEND completed"])
    assert code and code.uidvalidity == 38505 and code.dest == (3955,)
    assert find_code("COPYUID", [], [b"COPY completed"]) is None
    assert find_code("COPYUID", [b"1 1:2 5"], []) is None  # mismatched sets
    with pytest.raises(ValueError):
        expand("1:999999")


# ── header decoding ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,text",
    [
        ("=?utf-8?q?Caf=C3=A9?=", "Café"),
        ("=?UTF-8?B?w4lsb8Ovc2U=?=", "Éloïse"),
        ("=?utf-8?q?a?= =?utf-8?q?b?=", "ab"),  # whitespace between encoded words dropped
        ("=?utf-8?q?a?= plain =?utf-8?q?b?=", "a plain b"),
        ("=?UTF-8?Q?=C3?= =?UTF-8?Q?=A9t=C3=A9?=", "été"),  # character split across words
        ("=?iso-8859-1?q?r=E9sum=E9?=", "résumé"),
        ("=?utf-8*es?q?ma=C3=B1ana?=", "mañana"),  # RFC 2231 language
        ("=?x-unknown?q?caf=C3=A9?=", "café"),
        ("=?utf-8?b?not base64!!?=", "not base64!!"),  # stdlib's lenient reading
        ("Hello\r\n World", "Hello World"),
    ],
)
def test_decode_header(raw: str, text: str) -> None:
    assert mime.decode_header(raw) == text


@given(st.text(max_size=120))
def test_decode_header_never_crashes(raw: str) -> None:
    mime.decode_header(raw)


@given(st.binary(max_size=300), st.sampled_from([None, "utf-8", "iso-8859-1", "x-bogus", "shift_jis", "utf-16"]))
def test_decode_text_never_crashes(data: bytes, charset: str | None) -> None:
    assert isinstance(mime.decode_text(data, charset), str)


@given(st.binary(max_size=500), st.sampled_from(["base64", "quoted-printable", "7bit", "x-uuencode"]))
def test_transfer_decoding_never_crashes(data: bytes, cte: str) -> None:
    mime.decode_transfer(data, cte)
    mime.decode_partial_transfer(data, cte)


def test_partial_qp_and_base64() -> None:
    assert mime.decode_partial_transfer(b"caf=C3=A9 and =C", "quoted-printable") == "café and ".encode()
    assert mime.decode_text(b"caf\xc3\xa9 \xe2\x82", "utf-8") == "café "  # cut mid-character
    assert mime.decode_partial_transfer(b"aGVsbG8gd29y", "base64") == b"hello wor"
