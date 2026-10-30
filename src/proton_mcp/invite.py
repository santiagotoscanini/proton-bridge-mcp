"""Calendar invitations (iMIP, RFC 6047) read from a message, and the
METHOD:REPLY that answers one (RFC 5546 section 3.2.3)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from icalendar import Calendar, Event, vCalAddress, vText

from .errors import InvalidArgument, Refused
from .mime import normalize_address

MAX_ICS = 512 * 1024
PARTSTAT = {"accept": "ACCEPTED", "tentative": "TENTATIVE", "decline": "DECLINED"}
SUBJECT_PREFIX = {"accept": "Accepted", "tentative": "Tentatively accepted", "decline": "Declined"}


def _mailto(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("mailto:"):
        text = text[7:]
    return text.strip()


def _when(value: Any) -> str | None:
    if value is None:
        return None
    try:
        dt = value.dt if hasattr(value, "dt") else value
    except AttributeError:
        return None
    if isinstance(dt, datetime):
        return dt.isoformat()
    if isinstance(dt, date):
        return dt.isoformat()
    return str(dt)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@dataclass
class Invite:
    method: str
    uid: str
    sequence: int
    summary: str
    start: str | None
    end: str | None
    location: str
    organizer: str
    organizer_name: str
    attendees: list[dict[str, str]]
    invited_address: str | None
    your_status: str | None
    answerable_here: bool
    calendar: Calendar
    master: Event

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "uid": self.uid,
            "summary": self.summary,
            "start": self.start,
            "end": self.end,
            "location": self.location,
            "organizer": {"name": self.organizer_name, "address": self.organizer},
            "attendees": self.attendees,
            "your_status": self.your_status,
            "invited_address": self.invited_address,
            "answerable_here": self.answerable_here,
        }


def parse(data: bytes, own_addresses: tuple[str, ...], recipients: list[str]) -> Invite:
    """The invite in an iCalendar body. own_addresses are the account's;
    recipients are the message's Delivered-To/To/Cc, used to recognize the
    invited attendee when it is not one of the account's addresses."""
    if len(data) > MAX_ICS:
        raise InvalidArgument("the calendar part is too large to read")
    try:
        cal = Calendar.from_ical(data)
    except (ValueError, IndexError, KeyError) as exc:
        raise InvalidArgument(f"the calendar part does not parse: {exc}") from exc
    events = [c for c in cal.walk("VEVENT")]
    if not events:
        raise InvalidArgument("the calendar part has no event")
    master = next((e for e in events if "RECURRENCE-ID" not in e), events[0])
    organizer_prop = master.get("ORGANIZER")
    organizer = _mailto(organizer_prop)
    organizer_name = str(organizer_prop.params.get("CN", "")) if organizer_prop is not None else ""

    own = {normalize_address(a) for a in own_addresses}
    rcpt = {normalize_address(a) for a in recipients}
    attendees = []
    invited, status = None, None
    for att in _as_list(master.get("ATTENDEE")):
        addr = _mailto(att)
        partstat = str(att.params.get("PARTSTAT", "NEEDS-ACTION")).upper()
        attendees.append({"name": str(att.params.get("CN", "")), "address": addr, "status": partstat})
    for wanted in (own, rcpt):
        for a in attendees:
            if normalize_address(a["address"]) in wanted:
                invited, status = a["address"], a["status"]
                break
        if invited:
            break
    try:
        sequence = int(master.get("SEQUENCE", 0))
    except (TypeError, ValueError):
        sequence = 0
    end = master.get("DTEND")
    return Invite(
        method=str(cal.get("METHOD", "")).upper(),
        uid=str(master.get("UID", "")),
        sequence=sequence,
        summary=str(master.get("SUMMARY", "")),
        start=_when(master.get("DTSTART")),
        end=_when(end) if end is not None else None,
        location=str(master.get("LOCATION", "")),
        organizer=organizer,
        organizer_name=organizer_name,
        attendees=attendees[:100],
        invited_address=invited,
        your_status=status,
        answerable_here=bool(invited) and normalize_address(invited or "") in own,
        calendar=cal,
        master=master,
    )


def check_answerable(inv: Invite) -> None:
    """Refuse anything but a REQUEST to one of the account's addresses."""
    if inv.method != "REQUEST":
        raise Refused(f"this calendar message is a {inv.method or 'message without METHOD'}, not an invitation to answer")
    if not inv.uid:
        raise Refused("the invitation has no UID")
    if not inv.organizer or "@" not in inv.organizer:
        raise Refused("the invitation names no organizer to answer")
    if not inv.answerable_here:
        where = f" ({inv.invited_address})" if inv.invited_address else ""
        raise Refused(
            "this invitation was sent to an address that is not one of this Proton account's"
            f"{where}; answer it from the calendar that owns that address (for a Google address, Google Calendar)"
        )


def build_reply(inv: Invite, response: str, comment: str | None, now: datetime | None = None) -> bytes:
    """A METHOD:REPLY carrying the same UID and SEQUENCE, the organizer, and
    exactly one ATTENDEE: the invited address with the chosen PARTSTAT."""
    if response not in PARTSTAT:
        raise InvalidArgument("response must be accept, tentative or decline")
    master = inv.master
    reply = Calendar()
    reply.add("prodid", "-//proton-bridge-mcp//EN")
    reply.add("version", "2.0")
    reply.add("method", "REPLY")
    tzids = set()
    for prop in ("DTSTART", "DTEND", "RECURRENCE-ID"):
        value = master.get(prop)
        if value is not None and "TZID" in value.params:
            tzids.add(str(value.params["TZID"]))
    for tz in inv.calendar.walk("VTIMEZONE"):
        if str(tz.get("TZID")) in tzids:
            reply.add_component(tz)
    ev = Event()
    for prop in ("UID", "SEQUENCE", "RECURRENCE-ID", "DTSTART", "DTEND", "DURATION", "SUMMARY", "LOCATION", "ORGANIZER"):
        if prop in master:
            ev[prop] = master[prop]
    if "SEQUENCE" not in ev:
        ev.add("sequence", 0)
    ev.add("dtstamp", now or datetime.now(UTC))
    attendee = vCalAddress(f"mailto:{inv.invited_address}")
    attendee.params["PARTSTAT"] = vText(PARTSTAT[response])
    for a in _as_list(master.get("ATTENDEE")):
        if normalize_address(_mailto(a)) == normalize_address(inv.invited_address or "") and "CN" in a.params:
            attendee.params["CN"] = a.params["CN"]
    ev["ATTENDEE"] = attendee
    if comment:
        ev.add("comment", comment[:2000])
    reply.add_component(ev)
    return reply.to_ical()
