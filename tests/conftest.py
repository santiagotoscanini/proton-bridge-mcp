"""Shared fixtures: Bridge-shaped TLS material, a credentials endpoint, the
fake IMAP/SMTP servers, and a `Mail` wired to them."""

from __future__ import annotations

import http.server
import json
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from hypothesis import settings

HERE = Path(__file__).parent

# Builders vary in speed and the build tree is read-only afterwards: no
# per-example deadline (the HTML timing tests bound time themselves), no
# example database on disk.
settings.register_profile("build", deadline=None, database=None)
settings.load_profile("build")
sys.path.insert(0, str(HERE))

from fakeimap import FakeIMAP, Store, tls_context  # noqa: E402
from fakesmtp import FakeSMTP  # noqa: E402

from proton_mcp.credentials import EndpointSource  # noqa: E402
from proton_mcp.imapconn import Bridge  # noqa: E402
from proton_mcp.messages import DateCache  # noqa: E402
from proton_mcp.service import Mail  # noqa: E402

FIXTURES = HERE / "fixtures" / "eml"
ADDRESSES = ["me@example.com", "me.alias@example.org"]
PASSWORD = "bridge-pass-0001"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@dataclass(frozen=True)
class Cert:
    cert: Path
    key: Path

    @property
    def pem(self) -> str:
        return self.cert.read_text()


def make_cert(directory: Path, name: str, san: str = "IP:127.0.0.1") -> Cert:
    """A self-signed CA certificate with only an IP SAN — Bridge's shape."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to make test certificates")
    cert, key = directory / f"{name}.pem", directory / f"{name}.key"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "3650",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=127.0.0.1/O=Proton AG test",
            "-addext",
            f"subjectAltName={san}",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ],
        check=True,
        capture_output=True,
    )
    return Cert(cert, key)


@pytest.fixture(scope="session")
def certs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Cert]:
    d = tmp_path_factory.mktemp("tls")
    return {
        "bridge": make_cert(d, "bridge"),
        "other": make_cert(d, "other"),
        "dns": make_cert(d, "dns", "DNS:bridge.example.com"),
    }


class CredsServer(http.server.ThreadingHTTPServer):
    doc: dict[str, Any]
    hits: int


class _CredsHandler(http.server.BaseHTTPRequestHandler):
    server: CredsServer

    def do_GET(self) -> None:  # noqa: N802
        self.server.hits += 1
        if self.path != "/v1/account":
            self.send_error(404)
            return
        body = json.dumps(self.server.doc).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


def creds_doc(cert: Cert, imap_port: int, smtp_port: int, password: str = PASSWORD, ssl: bool = True) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "imap": {"host": "127.0.0.1", "port": imap_port, "ssl": ssl},
        "smtp": {"host": "127.0.0.1", "port": smtp_port, "ssl": ssl},
        "certificatePem": cert.pem,
        "accounts": [
            {"id": "acct-1", "username": "someuser", "state": "connected", "addresses": list(ADDRESSES), "password": password}
        ],
    }


@pytest.fixture()
def creds_server() -> Iterator[CredsServer]:
    srv = CredsServer(("127.0.0.1", 0), _CredsHandler)
    srv.doc, srv.hits = {}, 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


@dataclass
class Env:
    store: Store
    imap: FakeIMAP
    smtp: FakeSMTP
    creds: CredsServer
    bridge: Bridge
    mail: Mail
    sent: list[tuple[Any, ...]]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.creds.server_address[1]}/v1/account"


@pytest.fixture()
def env(certs: dict[str, Cert], creds_server: CredsServer) -> Iterator[Env]:
    tls = tls_context(str(certs["bridge"].cert), str(certs["bridge"].key))
    store = Store()
    imap = FakeIMAP(store, tls, PASSWORD, list(ADDRESSES)).start()
    smtp = FakeSMTP(tls, PASSWORD)
    creds_server.doc = creds_doc(certs["bridge"], imap.port, smtp.port)
    bridge = Bridge(EndpointSource(f"http://127.0.0.1:{creds_server.server_address[1]}/v1/account"), sleep=lambda s: None)
    sent: list[tuple[Any, ...]] = []
    mail = Mail(bridge, DateCache())
    yield Env(store, imap, smtp, creds_server, bridge, mail, sent)
    bridge.close()
    imap.stop()
    smtp.stop()
