"""Configuration: exactly one way to reach Bridge, both ways working, TLS
always pinned."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest
from conftest import ADDRESSES, PASSWORD, Cert, Env, creds_doc
from fakeimap import FakeIMAP, Store, tls_context

from proton_mcp import config
from proton_mcp.credentials import ConfigError, EndpointSource, StaticSource, ssl_context
from proton_mcp.errors import AuthFailed, BridgeUnavailable
from proton_mcp.imapconn import Bridge
from proton_mcp.messages import DateCache
from proton_mcp.service import Mail

TOKEN = "t" * 32


def static_env(tmp_path: Path, cert: Cert, imap_port: int, imap_ssl: bool = True, **extra: str) -> dict[str, str]:
    pw = tmp_path / "bridge-password"
    pw.write_text(PASSWORD + "\n")
    return {
        "PROTON_MCP_TOKEN": TOKEN,
        "PROTON_MCP_IMAP_HOST": "127.0.0.1",
        "PROTON_MCP_IMAP_PORT": str(imap_port),
        "PROTON_MCP_IMAP_SSL": "true" if imap_ssl else "false",
        "PROTON_MCP_SMTP_HOST": "127.0.0.1",
        "PROTON_MCP_SMTP_PORT": "1025",
        "PROTON_MCP_SMTP_SSL": "false",
        "PROTON_MCP_USERNAME": "me@example.com",
        "PROTON_MCP_PASSWORD_FILE": str(pw),
        "PROTON_MCP_CA_FILE": str(cert.cert),
        **extra,
    }


def test_token_required() -> None:
    with pytest.raises(ConfigError, match="PROTON_MCP_TOKEN"):
        config.load({"PROTON_MCP_CREDENTIALS_URL": "http://127.0.0.1:1189/v1/account"})
    with pytest.raises(ConfigError, match="PROTON_MCP_TOKEN"):
        config.load({"PROTON_MCP_TOKEN": "short", "PROTON_MCP_CREDENTIALS_URL": "http://127.0.0.1:1189/v1/account"})


def test_exactly_one_mode(tmp_path: Path, certs: dict) -> None:
    with pytest.raises(ConfigError, match="no way to reach Bridge"):
        config.load({"PROTON_MCP_TOKEN": TOKEN})
    both = static_env(tmp_path, certs["bridge"], 1143, PROTON_MCP_CREDENTIALS_URL="http://127.0.0.1:1189/v1/account")
    with pytest.raises(ConfigError, match="exactly one"):
        config.load(both)
    partial = {"PROTON_MCP_TOKEN": TOKEN, "PROTON_MCP_IMAP_HOST": "127.0.0.1", "PROTON_MCP_USERNAME": "me@example.com"}
    with pytest.raises(ConfigError, match="PROTON_MCP_CA_FILE"):
        config.load(partial)
    with pytest.raises(ConfigError, match="file"):
        config.load({**static_env(tmp_path, certs["bridge"], 1143), "PROTON_MCP_PASSWORD": "x"})
    with pytest.raises(ConfigError, match="true or false"):
        config.load(static_env(tmp_path, certs["bridge"], 1143, PROTON_MCP_IMAP_SSL="maybe"))
    with pytest.raises(ConfigError, match="port"):
        config.load(static_env(tmp_path, certs["bridge"], 1143, PROTON_MCP_IMAP_PORT="99999"))


def test_endpoint_mode_settings() -> None:
    s = config.load(
        {
            "PROTON_MCP_TOKEN": TOKEN,
            "PROTON_MCP_CREDENTIALS_URL": "http://127.0.0.1:1189/v1/account",
            "PROTON_MCP_LISTEN": "[::]:9000",
        }
    )
    assert isinstance(s.source, EndpointSource) and (s.listen_host, s.listen_port) == ("::", 9000)
    assert (config.load({"PROTON_MCP_TOKEN": TOKEN, "PROTON_MCP_CREDENTIALS_URL": "http://localhost:1/x"}).listen_port) == 8080
    for url in (
        "https://127.0.0.1:1189/v1/account",
        "http://bridge.example.com/v1/account",
        "http://10.0.0.5/x",
        "file:///etc/passwd",
    ):
        with pytest.raises(ConfigError):
            config.load({"PROTON_MCP_TOKEN": TOKEN, "PROTON_MCP_CREDENTIALS_URL": url})


def test_static_mode_settings(tmp_path: Path, certs: dict) -> None:
    s = config.load(static_env(tmp_path, certs["bridge"], 1143, PROTON_MCP_ADDRESSES="me@example.com, alias@example.org"))
    assert isinstance(s.source, StaticSource)
    creds = s.source.load()
    assert creds.login == "me@example.com" and creds.addresses == ("me@example.com", "alias@example.org")
    assert creds.password == PASSWORD and "bridge-pass" not in repr(creds)
    assert config.load(static_env(tmp_path, certs["bridge"], 1143)).source.load().addresses == ("me@example.com",)
    with pytest.raises(ConfigError):
        config.load(static_env(tmp_path, certs["bridge"], 1143, PROTON_MCP_ADDRESSES="not-an-address"))


def test_static_mode_end_to_end_over_starttls(tmp_path: Path, certs: dict) -> None:
    store = Store()
    store.add("INBOX", b"From: a@example.org\r\nSubject: hi\r\n\r\nbody\r\n", 1_790_000_000)
    srv = FakeIMAP(
        store, tls_context(str(certs["bridge"].cert), str(certs["bridge"].key)), PASSWORD, ["me@example.com"], implicit_tls=False
    ).start()
    bridge = Bridge(config.load(static_env(tmp_path, certs["bridge"], srv.port, imap_ssl=False)).source, sleep=lambda s: None)
    try:
        out = Mail(bridge, DateCache()).search({})
        assert [r["untrusted"]["subject"] for r in out["results"]] == ["hi"]
        sent = srv.sent()
        assert sent[0] == "STARTTLS"  # the first command: nothing before TLS
        assert any(c.startswith("LOGIN") for c in sent[1:])
        # A rotated password is read from the file again after a refused login.
        bridge.close()
        srv.password = "rotated-0002"
        (tmp_path / "bridge-password").write_text("rotated-0002")
        assert Mail(bridge, DateCache()).list_mailboxes()["mailboxes"]
    finally:
        bridge.close()
        srv.stop()


def test_starttls_refused_when_not_offered(tmp_path: Path, certs: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    import fakeimap

    store = Store()
    monkeypatch.setattr(fakeimap, "CAPS_PRE", b"IMAP4rev1 AUTH=PLAIN")
    srv = FakeIMAP(
        store, tls_context(str(certs["bridge"].cert), str(certs["bridge"].key)), PASSWORD, ["me@example.com"], implicit_tls=False
    ).start()
    bridge = Bridge(config.load(static_env(tmp_path, certs["bridge"], srv.port, imap_ssl=False)).source, sleep=lambda s: None)
    try:
        with pytest.raises(BridgeUnavailable, match="STARTTLS"):
            Mail(bridge).list_mailboxes()
        assert not any(c.startswith("LOGIN") for c in srv.sent())
    finally:
        srv.stop()


def test_wrong_password_everywhere_is_auth_failed(env: Env) -> None:
    env.creds.doc["accounts"][0]["password"] = "wrong-wrong-wrong"
    with pytest.raises(AuthFailed):
        env.mail.list_mailboxes()


def test_ssl_context_is_strict(certs: dict) -> None:
    ctx = ssl_context(certs["bridge"].pem)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_certificate_name_is_checked(env: Env, certs: dict) -> None:
    """A certificate valid only for a DNS name fails against the default
    name 127.0.0.1 even when pinned; PROTON_MCP_TLS_NAME names it."""
    store = Store()
    srv = FakeIMAP(store, tls_context(str(certs["dns"].cert), str(certs["dns"].key)), PASSWORD, list(ADDRESSES)).start()
    try:
        env.creds.doc = creds_doc(certs["dns"], srv.port, 1)
        with pytest.raises(BridgeUnavailable, match="pinned"):
            Mail(Bridge(EndpointSource(env.url), sleep=lambda s: None)).list_mailboxes()
        named = Bridge(EndpointSource(env.url, tls_name="bridge.example.com"), sleep=lambda s: None)
        assert Mail(named).list_mailboxes()["addresses"] == ADDRESSES
        named.close()
    finally:
        srv.stop()


def test_endpoint_documents_rejected(env: Env) -> None:
    for mutate in (
        lambda d: d.update(schemaVersion=2),
        lambda d: d["accounts"][0].pop("password"),
        lambda d: d.update(certificatePem="nope"),
        lambda d: d["imap"].update(port=0),
        lambda d: d["accounts"][0].update(addresses=[]),
    ):
        doc = {k: (v.copy() if isinstance(v, dict) else v) for k, v in env.creds.doc.items()}
        doc["accounts"] = [dict(a) for a in env.creds.doc["accounts"]]
        mutate(doc)
        saved, env.creds.doc = env.creds.doc, doc
        with pytest.raises(BridgeUnavailable):
            env.bridge.credentials(refresh=True)
        env.creds.doc = saved


def test_endpoint_unreachable() -> None:
    from fakeimap import free_port

    with pytest.raises(BridgeUnavailable, match="does not answer"):
        EndpointSource(f"http://127.0.0.1:{free_port()}/v1/account", timeout=1).load()
