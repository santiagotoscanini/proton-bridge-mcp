"""Where Bridge is and how to log in.

Two sources, exactly one configured:

- an HTTP endpoint on loopback that serves the account as JSON (for a
  supervisor that runs Bridge beside this server), fetched at start and
  again after an authentication failure or a reconnect;
- an explicit configuration: hosts and ports, the username, the password
  read from a file, and the certificate to pin read from a file.

Either way TLS is mandatory and pinned: the SSL context trusts exactly
Bridge's certificate. The password stays in memory and out of every repr."""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .errors import BridgeUnavailable

DEFAULT_TLS_NAME = "127.0.0.1"  # the only SAN on Bridge's own certificate
_MAX_RESPONSE = 1_000_000


class ConfigError(Exception):
    """The environment does not describe exactly one way to reach Bridge."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    implicit_tls: bool  # False: STARTTLS (still mandatory; never plaintext)


@dataclass(frozen=True)
class Credentials:
    imap: Endpoint
    smtp: Endpoint
    cert_pem: str
    tls_name: str
    login: str
    password: str = field(repr=False)
    addresses: tuple[str, ...]

    def __repr__(self) -> str:  # never the password
        return f"Credentials(login={self.login!r}, imap={self.imap}, smtp={self.smtp})"

    @property
    def primary(self) -> str:
        return self.addresses[0]


def ssl_context(cert_pem: str) -> ssl.SSLContext:
    """A client context that trusts exactly this certificate."""
    ctx = ssl.create_default_context(cadata=cert_pem)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class Source(Protocol):
    def load(self) -> Credentials: ...


def _port(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise ValueError(f"{what}: bad port")
    return value


def _host(value: object, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 255 or any(c in value for c in " /\r\n\x00"):
        raise ValueError(f"{what}: bad host")
    return value


def _cert(value: object) -> str:
    if not isinstance(value, str) or "-----BEGIN CERTIFICATE-----" not in value:
        raise ValueError("no PEM certificate")
    return value


def _addresses(values: object) -> tuple[str, ...]:
    if not isinstance(values, list) or not values:
        raise ValueError("account has no addresses")
    out = []
    for v in values:
        if not isinstance(v, str) or "@" not in v or any(c in v for c in " <>,\r\n\x00"):
            raise ValueError("bad address")
        out.append(v.strip())
    return tuple(out)


class EndpointSource:
    """A loopback HTTP endpoint serving
    {"schemaVersion":1,"imap":{host,port,ssl},"smtp":{…},"certificatePem":…,
     "accounts":[{"state":"connected","addresses":[…],"password":…}]}."""

    def __init__(self, url: str, timeout: float = 5.0, tls_name: str = DEFAULT_TLS_NAME) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ConfigError("PROTON_MCP_CREDENTIALS_URL must be an http:// URL on loopback")
        host = parsed.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            # It answers with a password over plain HTTP: loopback only.
            raise ConfigError("PROTON_MCP_CREDENTIALS_URL must point at a loopback address")
        self.url = url
        self.timeout = timeout
        self.tls_name = tls_name
        # No proxies: the request must never leave the host.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def load(self) -> Credentials:
        try:
            with self._opener.open(self.url, timeout=self.timeout) as resp:
                body = resp.read(_MAX_RESPONSE + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise BridgeUnavailable("the credentials endpoint does not answer") from exc
        if len(body) > _MAX_RESPONSE:
            raise BridgeUnavailable("the credentials endpoint answered too much")
        try:
            doc = json.loads(body)
            return self._parse(doc)
        except (ValueError, KeyError, TypeError) as exc:
            raise BridgeUnavailable(f"the credentials endpoint answered an unusable document: {exc}") from exc

    def _parse(self, doc: dict) -> Credentials:
        if doc.get("schemaVersion") != 1:
            raise ValueError("unsupported schemaVersion")
        imap, smtp = doc["imap"], doc["smtp"]
        cert = _cert(doc["certificatePem"])
        for account in doc.get("accounts") or []:
            if not isinstance(account, dict) or account.get("state") != "connected":
                continue
            password = account.get("password")
            if not isinstance(password, str) or not password:
                raise ValueError("connected account without a password")
            addresses = _addresses(account.get("addresses"))
            return Credentials(
                imap=Endpoint(_host(imap["host"], "imap"), _port(imap["port"], "imap"), bool(imap["ssl"])),
                smtp=Endpoint(_host(smtp["host"], "smtp"), _port(smtp["port"], "smtp"), bool(smtp["ssl"])),
                cert_pem=cert,
                tls_name=self.tls_name,
                # Bridge authenticates IMAP/SMTP logins against the account's
                # addresses, never against the Proton username.
                login=addresses[0],
                password=password,
                addresses=addresses,
            )
        states = sorted({str(a.get("state")) for a in doc.get("accounts") or [] if isinstance(a, dict)})
        raise BridgeUnavailable("Bridge has no connected account" + (f" (states: {', '.join(states)})" if states else ""))


class StaticSource:
    """Explicit configuration. The password and the certificate are files,
    read again on every load (after an authentication failure, say)."""

    def __init__(
        self,
        imap: Endpoint,
        smtp: Endpoint,
        username: str,
        password_file: Path,
        ca_file: Path,
        addresses: tuple[str, ...],
        tls_name: str = DEFAULT_TLS_NAME,
    ) -> None:
        self.imap, self.smtp = imap, smtp
        self.username = username
        self.password_file, self.ca_file = password_file, ca_file
        self.addresses = addresses
        self.tls_name = tls_name

    def load(self) -> Credentials:
        try:
            password = self.password_file.read_text(encoding="utf-8").strip()
            cert = _cert(self.ca_file.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise BridgeUnavailable(f"cannot read the configured password or certificate file: {exc}") from exc
        if not password:
            raise BridgeUnavailable("the password file is empty")
        return Credentials(
            imap=self.imap,
            smtp=self.smtp,
            cert_pem=cert,
            tls_name=self.tls_name,
            login=self.username,
            password=password,
            addresses=self.addresses,
        )
