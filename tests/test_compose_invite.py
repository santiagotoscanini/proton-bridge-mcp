"""Draft builders, the iCalendar reply, and the one send path."""

from __future__ import annotations

import email
import email.policy
from datetime import UTC, datetime

import pytest
from conftest import ADDRESSES, Env, fixture
from icalendar import Calendar

from proton_mcp import compose, invite, smtpsend
from proton_mcp.errors import InvalidArgument, Refused
from proton_mcp.mime import Headers, parse_message

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
OWN = tuple(ADDRESSES)


def headers(raw: bytes) -> Headers:
    return parse_message(raw)[0]


def test_subjects() -> None:
    assert compose.reply_subject("Budget") == "Re: Budget"
    assert compose.reply_subject("RE: Budget") == "RE: Budget"
    assert compose.reply_subject("Aw: Budget") == "Aw: Budget"
    assert compose.reply_subject("") == "Re:"
    assert compose.forward_subject("Budget") == "Fwd: Budget"
    assert compose.forward_subject("FW: Budget") == "FW: Budget"
    assert compose.reply_subject("Line\r\nBcc: evil@example.net") == "Re: Line Bcc: evil@example.net"


def test_thread_headers_drop_bridge_self_reference() -> None:
    irt, refs = compose.thread_headers(headers(fixture("bridge-shapes.eml")))
    assert irt == "<bridgeInternal123==@protonmail.internalid>"
    assert refs == "<thread-root-9@example.org> <bridgeInternal123==@protonmail.internalid>"
    irt, refs = compose.thread_headers(headers(fixture("reply-thread.eml")))
    assert irt == "<reply-3@example.org>" and refs == "<reply-1@example.org> <reply-2@example.com> <reply-3@example.org>"
    many = b"Message-ID: <m@x.example>\r\nReferences: " + b" ".join(b"<r%d@x.example>" % i for i in range(40)) + b"\r\n\r\n"
    _, refs = compose.thread_headers(headers(many))
    assert refs is not None and refs.count("<") == 20 and refs.endswith("<m@x.example>")
    assert compose.thread_headers(headers(b"Subject: x\r\n\r\n")) == (None, None)


def test_reply_recipients() -> None:
    h = headers(fixture("reply-thread.eml"))
    to, cc = compose.reply_recipients(h, OWN, reply_all=False)
    assert [a.address for a in to] == ["pat@example.org"] and cc == []
    to, cc = compose.reply_recipients(h, OWN, reply_all=True)
    assert [a.address for a in cc] == ["quinn@example.net", "rae@example.com"]
    to, _ = compose.reply_recipients(headers(fixture("bridge-shapes.eml")), OWN, False)
    assert [a.address for a in to] == ["replies@example.org"]  # Reply-To wins
    mine = b"From: Me <ME+tag@example.com>\r\nTo: x@example.net, me.alias@example.org\r\n\r\n"
    to, _ = compose.reply_recipients(headers(mine), OWN, False)
    assert [a.address for a in to] == ["x@example.net"]  # own message: reply goes to its recipients


def test_from_and_recipients_validation() -> None:
    assert compose.choose_from(None, OWN, OWN[0]) == "me@example.com"
    assert compose.choose_from("ME.ALIAS@example.org", OWN, OWN[0]) == "me.alias@example.org"
    with pytest.raises(Refused):
        compose.choose_from("someone@example.net", OWN, OWN[0])
    got = compose.parse_recipients(["Ann <ann@example.com>", "bob@example.org, ann@example.com"], "to")
    assert [(a.name, a.address) for a in got] == [("Ann", "ann@example.com"), ("", "bob@example.org")]
    for bad in (["not an address"], ["a@b"], ["x@example.com\r\nBcc: y@example.com"], [""], [7]):
        with pytest.raises(InvalidArgument):
            compose.parse_recipients(bad, "to")  # type: ignore[arg-type]


def test_message_is_clean_mime() -> None:
    to = compose.parse_recipients(["Zoë <zoe@example.com>"], "to")
    msg = compose.message("me@example.com", to, [], [], "Café ☕", "Hola\nñandú " + "x" * 200, NOW)
    raw = compose.to_bytes(msg)
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert parsed["Subject"] == "Café ☕" and parsed["To"].addresses[0].display_name == "Zoë"
    assert parsed.get_content().replace("\r\n", "\n").startswith("Hola\nñandú")
    assert b"\r\n" in raw and b"X-Pm-" not in raw and raw.isascii()
    assert parsed["Message-ID"].endswith("@example.com>")
    with pytest.raises(InvalidArgument):
        compose.message("me@example.com", to, [], [], "s", "x" * 100_001, NOW)
    with pytest.raises(InvalidArgument):
        compose.message("me@example.com", to * 101, [], [], "s", "b", NOW)


def test_attach_sanitizes() -> None:
    msg = compose.message("me@example.com", compose.parse_recipients(["a@example.com"], "to"), [], [], "s", "b", NOW)
    compose.attach(
        msg,
        [
            compose.FileAttachment("../../etc/passwd\r\n", "multipart/mixed", b"x"),
            compose.FileAttachment("ok.pdf", "application/pdf", b"%PDF"),
        ],
    )
    parts = list(email.message_from_bytes(compose.to_bytes(msg), policy=email.policy.default).iter_attachments())
    assert parts[0].get_content_type() == "application/octet-stream" and "/" not in parts[0].get_filename()
    assert parts[1].get_filename() == "ok.pdf"


# ── invitations ──────────────────────────────────────────────────────────


def _invite(name: str) -> invite.Invite:
    raw = fixture(name)
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    for part in msg.walk():
        if part.get_content_type() == "text/calendar":
            return invite.parse(part.get_payload(decode=True), OWN, [])
    raise AssertionError("no calendar part")


def test_invite_parse() -> None:
    inv = _invite("invite-request.eml")
    assert (inv.method, inv.uid, inv.sequence, inv.summary) == (
        "REQUEST",
        "planning-session-42@example.org",
        2,
        "Planning session",
    )
    assert inv.start == "2026-11-03T10:00:00-03:00" and inv.location == "Room 4"
    assert inv.organizer == "organizer@example.org" and inv.organizer_name == "Olivia Organizer"
    assert inv.invited_address == "me@example.com" and inv.your_status == "NEEDS-ACTION" and inv.answerable_here
    other = _invite("invite-other-address.eml")
    assert other.invited_address is None and not other.answerable_here
    with pytest.raises(Refused, match="Google Calendar"):
        invite.check_answerable(other)
    with pytest.raises(InvalidArgument):
        invite.parse(b"not a calendar", OWN, [])
    with pytest.raises(InvalidArgument):
        invite.parse(b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", OWN, [])


def test_invited_address_from_recipients_when_not_own() -> None:
    raw = fixture("invite-other-address.eml")
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    part = next(p for p in msg.walk() if p.get_content_type() == "text/calendar")
    inv = invite.parse(part.get_payload(decode=True), OWN, ["someone.else@example.net"])
    assert inv.invited_address == "someone.else@example.net" and not inv.answerable_here


@pytest.mark.parametrize("response,partstat", [("accept", "ACCEPTED"), ("tentative", "TENTATIVE"), ("decline", "DECLINED")])
def test_build_reply(response: str, partstat: str) -> None:
    inv = _invite("invite-request.eml")
    ics = invite.build_reply(inv, response, "See you" if response == "accept" else None, NOW)
    cal = Calendar.from_ical(ics)
    assert str(cal["METHOD"]) == "REPLY"
    ev = next(iter(cal.walk("VEVENT")))
    assert str(ev["UID"]) == "planning-session-42@example.org" and int(ev["SEQUENCE"]) == 2
    attendees = ev.get("ATTENDEE")
    assert not isinstance(attendees, list)
    assert str(attendees).lower() == "mailto:me@example.com" and str(attendees.params["PARTSTAT"]) == partstat
    assert str(attendees.params["CN"]) == "Me Example"
    assert str(ev["ORGANIZER"]).lower() == "mailto:organizer@example.org"
    assert "DESCRIPTION" not in ev  # nothing from the invite's free text travels back
    assert [str(tz["TZID"]) for tz in cal.walk("VTIMEZONE")] == ["America/Montevideo"]
    assert ev.decoded("DTSTAMP") == NOW
    with pytest.raises(InvalidArgument):
        invite.build_reply(inv, "maybe", None, NOW)


# ── the one send ─────────────────────────────────────────────────────────


@pytest.fixture()
def invited(env: Env) -> str:
    env.store.add("INBOX", fixture("invite-request.eml"), 1_790_000_000)
    env.store.add("INBOX", fixture("invite-other-address.eml"), 1_790_000_100)
    env.store.add("INBOX", fixture("invite-cancel.eml"), 1_790_000_200)
    env.store.add("INBOX", fixture("plain-ascii.eml"), 1_790_000_300)
    env.imap.clear()
    return env.mail.search({"subject": "Planning session @"})["results"][0]["id"]


def test_respond_to_invite_sends_one_fixed_reply(env: Env, invited: str) -> None:
    out = env.mail.respond_to_invite(invited, "accept")
    assert out == {
        "sent": True,
        "response": "accept",
        "from": "me@example.com",
        "to": "organizer@example.org",
        "untrusted": {"summary": "Planning session", "start": "2026-11-03T10:00:00-03:00"},
    }
    (s,) = env.smtp.sessions
    assert s.login == "me@example.com" and s.mail_from == "me@example.com" and s.rcpt == ["organizer@example.org"]
    msg = email.message_from_bytes(s.data, policy=email.policy.default)
    assert msg["To"].addresses[0].addr_spec == "organizer@example.org" and msg["Cc"] is None and msg["Bcc"] is None
    assert msg["Subject"] == "Accepted: Planning session"
    cal = next(p for p in msg.walk() if p.get_content_type() == "text/calendar")
    assert cal.get_param("method") == "REPLY" and b"PARTSTAT=ACCEPTED" in cal.get_content().encode()
    # The IMAP side stayed read-only: no SELECT, STORE, APPEND, ...
    words = {c.split()[0] for c in env.imap.sent()}
    assert words <= {"CAPABILITY", "LOGIN", "LIST", "EXAMINE", "UID", "NOOP", "UNSELECT"}
    assert not any(c.startswith(("UID STORE", "UID COPY", "UID MOVE")) for c in env.imap.sent())


def test_respond_to_invite_refusals_never_touch_smtp(env: Env, invited: str) -> None:
    other = env.mail.search({"subject": "Offsite"})["results"][0]["id"]
    with pytest.raises(Refused, match="Google Calendar"):
        env.mail.respond_to_invite(other, "accept")
    cancel = env.mail.search({"subject": "Canceled"})["results"][0]["id"]
    with pytest.raises(Refused, match="CANCEL"):
        env.mail.respond_to_invite(cancel, "decline")
    plain = env.mail.search({"subject": "Lunch"})["results"][0]["id"]
    with pytest.raises(Refused, match="no calendar"):
        env.mail.respond_to_invite(plain, "accept")
    with pytest.raises(InvalidArgument):
        env.mail.respond_to_invite(invited, "yes please")
    assert env.smtp.sessions == []


def test_send_path_enforces_its_fixed_envelope(env: Env, invited: str) -> None:
    creds = env.bridge.credentials()
    good = compose.to_bytes(
        compose.invite_reply_message(
            "me@example.com", "", "organizer@example.org", "", "Accepted: x", "ok", b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", NOW
        )
    )
    with pytest.raises(Refused):
        smtpsend.send_invite_reply(creds, "me@example.com", "someone@example.net", good)  # To != recipient
    with pytest.raises(Refused):
        smtpsend.send_invite_reply(creds, "stranger@example.net", "organizer@example.org", good)
    with_cc = good.replace(b"To: organizer@example.org", b"To: organizer@example.org\r\nCc: extra@example.net")
    with pytest.raises(Refused):
        smtpsend.send_invite_reply(creds, "me@example.com", "organizer@example.org", with_cc)
    assert env.smtp.sessions == []
    # The SMTP object itself refuses any other envelope.
    conn = smtpsend._FixedSMTP_SSL(creds, "me@example.com", "organizer@example.org")
    try:
        with pytest.raises(Refused):
            conn.mail("other@example.com")
        conn.mail("me@example.com")
        with pytest.raises(Refused):
            conn.rcpt("extra@example.net")
    finally:
        conn.close()


def test_smtp_rejection_and_starttls(env: Env, invited: str, certs: dict) -> None:
    env.smtp.reject.add("organizer@example.org")
    with pytest.raises(Refused, match="organizer"):
        env.mail.respond_to_invite(invited, "decline")
    from fakeimap import tls_context
    from fakesmtp import FakeSMTP

    plain = FakeSMTP(tls_context(str(certs["bridge"].cert), str(certs["bridge"].key)), "bridge-pass-0001", implicit_tls=False)
    try:
        env.creds.doc["smtp"] = {"host": "127.0.0.1", "port": plain.port, "ssl": False}
        env.bridge.forget_credentials()
        env.mail.respond_to_invite(invited, "tentative")
        assert "STARTTLS" in plain.sessions[-1].commands and plain.sessions[-1].rcpt == ["organizer@example.org"]
    finally:
        plain.stop()
