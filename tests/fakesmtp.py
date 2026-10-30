"""A minimal SMTP server (implicit TLS or STARTTLS) that records sessions."""

from __future__ import annotations

import base64
import socketserver
import ssl
import threading
from dataclasses import dataclass, field


@dataclass
class Session:
    login: str | None = None
    mail_from: str | None = None
    rcpt: list[str] = field(default_factory=list)
    data: bytes = b""
    commands: list[str] = field(default_factory=list)


class _Handler(socketserver.StreamRequestHandler):
    server: FakeSMTP

    def setup(self) -> None:
        if self.server.implicit_tls:
            self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        super().setup()

    def line(self, text: str) -> None:
        self.wfile.write(text.encode() + b"\r\n")
        self.wfile.flush()

    def handle(self) -> None:
        s = Session()
        self.server.sessions.append(s)
        self.line("220 fake ESMTP ready")
        tls_done = self.server.implicit_tls
        while True:
            raw = self.rfile.readline(65536)
            if not raw:
                return
            cmd = raw.decode("latin-1").rstrip("\r\n")
            verb = cmd.split(" ", 1)[0].upper()
            s.commands.append(verb if verb != "AUTH" else "AUTH <redacted>")
            if verb in ("EHLO", "HELO"):
                exts = ["250-fake", "250-AUTH PLAIN LOGIN"]
                if not tls_done:
                    exts.append("250-STARTTLS")
                exts.append("250 8BITMIME")
                for e in exts:
                    self.line(e)
            elif verb == "STARTTLS":
                self.line("220 go ahead")
                self.request = self.server.tls.wrap_socket(self.request, server_side=True)
                self.rfile = self.request.makefile("rb")
                self.wfile = self.request.makefile("wb")
                tls_done = True
            elif verb == "AUTH":
                parts = cmd.split()
                if len(parts) >= 3 and parts[1].upper() == "PLAIN":
                    _, user, password = base64.b64decode(parts[2]).decode().split("\x00")
                    if password == self.server.password:
                        s.login = user
                        self.line("235 ok")
                    else:
                        self.line("535 bad credentials")
                else:
                    self.line("504 only PLAIN")
            elif verb == "MAIL":
                s.mail_from = cmd.split(":", 1)[1].strip().strip("<>").split(">")[0]
                self.line("250 ok")
            elif verb == "RCPT":
                addr = cmd.split(":", 1)[1].strip().strip("<>").split(">")[0]
                if addr in self.server.reject:
                    self.line("550 no")
                else:
                    s.rcpt.append(addr)
                    self.line("250 ok")
            elif verb == "DATA":
                self.line("354 end with .")
                buf = bytearray()
                while True:
                    ln = self.rfile.readline(1 << 20)
                    if ln in (b".\r\n", b".\n", b""):
                        break
                    buf += ln[1:] if ln.startswith(b"..") else ln
                s.data = bytes(buf)
                self.line("250 queued")
            elif verb == "QUIT":
                self.line("221 bye")
                return
            else:
                self.line("250 ok")


class FakeSMTP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, tls: ssl.SSLContext, password: str, implicit_tls: bool = True) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.tls = tls
        self.password = password
        self.implicit_tls = implicit_tls
        self.sessions: list[Session] = []
        self.reject: set[str] = set()
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
