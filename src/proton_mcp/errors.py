"""Typed errors. Every failure a tool reports has a `kind` the model can act on."""

from __future__ import annotations

from typing import Any


class MailError(Exception):
    """Base of every error a tool returns to the model."""

    kind = "error"

    def __init__(self, message: str, **detail: Any) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": self.kind, "message": self.message}
        out.update(self.detail)
        return out


class BridgeUnavailable(MailError):
    """Bridge's listener refuses, dropped the connection, or timed out.

    `outcome="unknown"` when a write was already on the wire."""

    kind = "bridge_unavailable"


class AuthFailed(MailError):
    kind = "auth_failed"


class InvalidId(MailError):
    kind = "invalid_id"


class StaleId(MailError):
    """The mailbox's UIDVALIDITY changed and the message could not be re-found."""

    kind = "stale_id"


class NotFound(MailError):
    kind = "not_found"


class InvalidArgument(MailError):
    kind = "invalid_argument"


class Refused(MailError):
    """The request is well-formed but this server will not do it."""

    kind = "refused"


class TooLarge(MailError):
    kind = "too_large"


class ImapError(MailError):
    """Bridge answered NO or BAD."""

    kind = "imap_error"


class GuardViolation(MailError):
    """A tool tried to send an IMAP command outside its allowlist.

    Raised before a single byte leaves the process; it is a bug in this
    server, never something the model caused."""

    kind = "guard_violation"
