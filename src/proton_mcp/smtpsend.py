"""The server's only send: an iCalendar reply to an invitation's organizer.

SMTP is reached through `send_invite_reply` alone, which respond_to_invite
calls. The SMTP object it builds accepts exactly one envelope sender and
one recipient, fixed before the connection opens; MAIL FROM or RCPT TO
with anything else raises before it is sent."""

from __future__ import annotations

import email
import email.policy
import smtplib
import socket
import ssl

from .credentials import Credentials, ssl_context
from .errors import AuthFailed, BridgeUnavailable, Refused
from .mime import Headers, normalize_address

TIMEOUT = 60.0
MAX_MESSAGE = 1024 * 1024


class _Fixed:
    """Pins the envelope: one sender, one recipient."""

    fixed_sender: str
    fixed_recipient: str

    def mail(self, sender, options=()):  # type: ignore[no-untyped-def]
        if normalize_address(sender) != normalize_address(self.fixed_sender) or options:
            raise Refused("SMTP sender is not the invited address")
        return super().mail(sender, options)  # type: ignore[misc]

    def rcpt(self, recip, options=()):  # type: ignore[no-untyped-def]
        if normalize_address(recip) != normalize_address(self.fixed_recipient) or options:
            raise Refused("SMTP recipient is not the organizer")
        return super().rcpt(recip, options)  # type: ignore[misc]


class _FixedSMTP_SSL(_Fixed, smtplib.SMTP_SSL):
    def __init__(self, creds: Credentials, sender: str, recipient: str) -> None:
        self.fixed_sender, self.fixed_recipient = sender, recipient
        self._tls_name = creds.tls_name
        super().__init__(creds.smtp.host, creds.smtp.port, context=ssl_context(creds.cert_pem), timeout=TIMEOUT)

    def _get_socket(self, host, port, timeout):  # type: ignore[no-untyped-def]
        sock = socket.create_connection((host, port), timeout, self.source_address)
        return self.context.wrap_socket(sock, server_hostname=self._tls_name)


class _FixedSMTP_STARTTLS(_Fixed, smtplib.SMTP):
    def __init__(self, creds: Credentials, sender: str, recipient: str) -> None:
        self.fixed_sender, self.fixed_recipient = sender, recipient
        super().__init__(creds.smtp.host, creds.smtp.port, timeout=TIMEOUT)
        self.ehlo()
        if not self.has_extn("starttls"):
            self.close()
            raise ssl.SSLError("server does not offer STARTTLS")
        self._host = creds.tls_name  # the name the certificate is checked against
        self.starttls(context=ssl_context(creds.cert_pem))
        self.ehlo()


def send_invite_reply(creds: Credentials, sender: str, recipient: str, message: bytes) -> None:
    if normalize_address(sender) not in {normalize_address(a) for a in creds.addresses}:
        raise Refused("the reply must come from one of this account's addresses")
    if len(message) > MAX_MESSAGE:
        raise Refused("the reply is too large")
    headers = Headers(list(email.message_from_bytes(message, policy=email.policy.compat32).raw_items()))
    to = headers.addresses("To")
    if (
        len(to) != 1
        or normalize_address(to[0].address) != normalize_address(recipient)
        or headers.raw_all("Cc")
        or headers.raw_all("Bcc")
        or [normalize_address(a.address) for a in headers.addresses("From")] != [normalize_address(sender)]
    ):
        raise Refused("the reply's headers do not match its fixed sender and recipient")
    impl = _FixedSMTP_SSL if creds.smtp.implicit_tls else _FixedSMTP_STARTTLS
    try:
        smtp = impl(creds, sender, recipient)
    except ssl.SSLCertVerificationError as exc:
        raise BridgeUnavailable(f"Bridge's certificate does not match the pinned one: {exc.verify_message}") from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise BridgeUnavailable(f"cannot reach Bridge's SMTP listener: {type(exc).__name__}") from exc
    try:
        try:
            smtp.login(creds.login, creds.password)
        except smtplib.SMTPAuthenticationError as exc:
            raise AuthFailed("Bridge's SMTP refused the login") from exc
        except (smtplib.SMTPException, OSError) as exc:
            raise BridgeUnavailable(f"SMTP login failed: {type(exc).__name__}") from exc
        try:
            refused = smtp.sendmail(sender, [recipient], message)
        except smtplib.SMTPRecipientsRefused as exc:
            raise Refused("Bridge refused the organizer as a recipient") from exc
        except (smtplib.SMTPException, OSError) as exc:
            raise BridgeUnavailable(f"sending through Bridge failed: {type(exc).__name__}", outcome="unknown") from exc
        if refused:
            raise Refused("Bridge refused the organizer as a recipient")
    finally:
        try:
            smtp.quit()
        except (smtplib.SMTPException, OSError):
            smtp.close()
