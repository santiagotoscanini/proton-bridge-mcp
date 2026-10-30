"""Opaque message ids.

An id names one message as one mailbox sees it: mailbox, UIDVALIDITY, UID,
the message's INTERNALDATE (epoch seconds, to re-find it cheaply) and
Bridge's X-Pm-Internal-Id (stable across resyncs and mailboxes). The model
treats it as an opaque string; every use re-checks UIDVALIDITY."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from .errors import InvalidId

PREFIX = "m1."
_SEP = "\x1f"
_MAX_ID = 2048
_INTERNAL_ID = re.compile(r"[A-Za-z0-9_\-+/=.@]{0,256}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class MessageRef:
    mailbox: str
    uidvalidity: int
    uid: int
    date: int  # INTERNALDATE, epoch seconds
    internal_id: str  # X-Pm-Internal-Id, "" when the message has none

    def encode(self) -> str:
        validate_mailbox(self.mailbox)
        raw = _SEP.join([str(self.uidvalidity), str(self.uid), str(self.date), self.internal_id, self.mailbox]).encode("utf-8")
        return PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def validate_mailbox(name: str) -> None:
    if not name or len(name) > 512 or _CONTROL.search(name):
        raise InvalidId("bad mailbox name in id")


def decode(value: object) -> MessageRef:
    if not isinstance(value, str) or not value.startswith(PREFIX) or len(value) > _MAX_ID:
        raise InvalidId("not a message id from this server")
    body = value[len(PREFIX) :]
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", body):
        raise InvalidId("not a message id from this server")
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidId("not a message id from this server") from exc
    parts = raw.split(_SEP)
    if len(parts) != 5:
        raise InvalidId("not a message id from this server")
    uidvalidity_s, uid_s, date_s, internal_id, mailbox = parts
    try:
        uidvalidity, uid, date = int(uidvalidity_s), int(uid_s), int(date_s)
    except ValueError as exc:
        raise InvalidId("not a message id from this server") from exc
    if not (0 < uidvalidity < 2**32 and 0 < uid < 2**32 and 0 <= date < 2**40):
        raise InvalidId("not a message id from this server")
    if not all(s.isdigit() for s in (uidvalidity_s, uid_s, date_s)):
        raise InvalidId("not a message id from this server")
    if not _INTERNAL_ID.fullmatch(internal_id):
        raise InvalidId("not a message id from this server")
    validate_mailbox(mailbox)
    return MessageRef(mailbox, uidvalidity, uid, date, internal_id)
