"""Settings from the environment. Anything ambiguous refuses to start."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .credentials import DEFAULT_TLS_NAME, ConfigError, Endpoint, EndpointSource, Source, StaticSource

STATIC_VARS = (
    "PROTON_MCP_IMAP_HOST",
    "PROTON_MCP_IMAP_PORT",
    "PROTON_MCP_IMAP_SSL",
    "PROTON_MCP_SMTP_HOST",
    "PROTON_MCP_SMTP_PORT",
    "PROTON_MCP_SMTP_SSL",
    "PROTON_MCP_USERNAME",
    "PROTON_MCP_PASSWORD_FILE",
    "PROTON_MCP_CA_FILE",
)
_OPTIONAL_STATIC = ("PROTON_MCP_ADDRESSES",)
MIN_TOKEN = 16


@dataclass(frozen=True)
class Settings:
    token: str
    listen_host: str
    listen_port: int
    source: Source


def _bool(name: str, value: str) -> bool:
    v = value.strip().lower()
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    raise ConfigError(f"{name} must be true or false (false = STARTTLS; plaintext is never used)")


def _port(name: str, value: str) -> int:
    if not value.strip().isdigit() or not 0 < int(value) < 65536:
        raise ConfigError(f"{name} must be a TCP port")
    return int(value)


def _listen(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise ConfigError("PROTON_MCP_LISTEN must be host:port")
    return host.strip("[]"), _port("PROTON_MCP_LISTEN", port)


def _static(env: Mapping[str, str], tls_name: str) -> StaticSource:
    missing = [k for k in STATIC_VARS if not env.get(k, "").strip()]
    if missing:
        raise ConfigError("explicit configuration is incomplete; missing " + ", ".join(missing))
    username = env["PROTON_MCP_USERNAME"].strip()
    addresses = tuple(a.strip() for a in env.get("PROTON_MCP_ADDRESSES", "").split(",") if a.strip())
    if not addresses:
        addresses = (username,)
    for addr in addresses:
        if "@" not in addr or any(c in addr for c in " <>\r\n"):
            raise ConfigError("PROTON_MCP_ADDRESSES must be a comma-separated list of addresses")
    return StaticSource(
        imap=Endpoint(
            env["PROTON_MCP_IMAP_HOST"].strip(),
            _port("PROTON_MCP_IMAP_PORT", env["PROTON_MCP_IMAP_PORT"]),
            _bool("PROTON_MCP_IMAP_SSL", env["PROTON_MCP_IMAP_SSL"]),
        ),
        smtp=Endpoint(
            env["PROTON_MCP_SMTP_HOST"].strip(),
            _port("PROTON_MCP_SMTP_PORT", env["PROTON_MCP_SMTP_PORT"]),
            _bool("PROTON_MCP_SMTP_SSL", env["PROTON_MCP_SMTP_SSL"]),
        ),
        username=username,
        password_file=Path(env["PROTON_MCP_PASSWORD_FILE"].strip()),
        ca_file=Path(env["PROTON_MCP_CA_FILE"].strip()),
        addresses=addresses,
        tls_name=tls_name,
    )


def load_source(env: Mapping[str, str] | None = None) -> Source:
    """How to reach Bridge: exactly one of the two modes, or ConfigError."""
    env = os.environ if env is None else env
    if "PROTON_MCP_PASSWORD" in env:
        raise ConfigError("PROTON_MCP_PASSWORD is not read: put the password in a file, PROTON_MCP_PASSWORD_FILE")
    tls_name = env.get("PROTON_MCP_TLS_NAME", "").strip() or DEFAULT_TLS_NAME
    url = env.get("PROTON_MCP_CREDENTIALS_URL", "").strip()
    static_given = [k for k in STATIC_VARS + _OPTIONAL_STATIC if env.get(k, "").strip()]
    if url and static_given:
        raise ConfigError(
            "configure exactly one way to reach Bridge: PROTON_MCP_CREDENTIALS_URL or the explicit "
            "PROTON_MCP_IMAP_*/SMTP_*/USERNAME/PASSWORD_FILE/CA_FILE set, not both"
        )
    if url:
        return EndpointSource(url, tls_name=tls_name)
    if static_given:
        return _static(env, tls_name)
    raise ConfigError(
        "no way to reach Bridge: set PROTON_MCP_CREDENTIALS_URL, or PROTON_MCP_IMAP_HOST/_PORT/_SSL, "
        "PROTON_MCP_SMTP_HOST/_PORT/_SSL, PROTON_MCP_USERNAME, PROTON_MCP_PASSWORD_FILE and PROTON_MCP_CA_FILE"
    )


def load(env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    token = env.get("PROTON_MCP_TOKEN", "")
    if len(token) < MIN_TOKEN:
        raise ConfigError(f"PROTON_MCP_TOKEN must be set (at least {MIN_TOKEN} characters)")
    host, port = _listen(env.get("PROTON_MCP_LISTEN", "0.0.0.0:8080"))
    return Settings(token=token, listen_host=host, listen_port=port, source=load_source(env))
