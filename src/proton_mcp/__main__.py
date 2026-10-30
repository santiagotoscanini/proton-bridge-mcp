"""proton-mcp: run the server."""

from __future__ import annotations

import logging
import sys

import uvicorn

from . import config
from .credentials import ConfigError
from .errors import MailError
from .imapconn import Bridge
from .server import build_app
from .service import Mail


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        settings = config.load()
    except ConfigError as exc:
        print(f"proton-mcp: {exc}", file=sys.stderr)
        sys.exit(2)
    bridge = Bridge(settings.source)
    try:
        creds = bridge.credentials()
        logging.getLogger("proton_mcp").info(
            "Bridge account loaded: %d address(es), IMAP %s, SMTP %s",
            len(creds.addresses),
            "TLS" if creds.imap.implicit_tls else "STARTTLS",
            "TLS" if creds.smtp.implicit_tls else "STARTTLS",
        )
    except MailError as exc:
        # Not fatal: Bridge may still be starting. healthz reports it until it answers.
        logging.getLogger("proton_mcp").warning("Bridge credentials not available yet: %s", exc.message)
    app = build_app(settings.token, bridge, Mail(bridge))
    uvicorn.run(app, host=settings.listen_host, port=settings.listen_port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
