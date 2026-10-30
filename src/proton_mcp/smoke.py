"""proton-mcp-smoke: a read-only check against a live Bridge.

Runs the five read tools on real mail and prints only counts, timings and
shapes — never a subject, address, body, filename or the password. Every
call runs under the read policy, so the command guard would refuse any
write; at the end it asserts every mailbox's unread count is unchanged,
which proves no read set \\Seen.

Configure it like the server (PROTON_MCP_CREDENTIALS_URL, or the explicit
PROTON_MCP_IMAP_* set); PROTON_MCP_TOKEN is not needed."""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from . import config
from .credentials import ConfigError
from .errors import MailError
from .imapconn import Bridge
from .service import Mail


def _timed(label: str, fn: Callable[[], Any]) -> Any:
    start = time.monotonic()
    try:
        result = fn()
    except MailError as exc:
        print(f"{label}: ERROR {exc.kind} after {time.monotonic() - start:.2f}s")
        raise
    print(f"{label}: {time.monotonic() - start:.2f}s", end="")
    return result


def _unseen(mail: Mail) -> dict[str, int]:
    return {m["name"]: m["unseen"] for m in mail.list_mailboxes()["mailboxes"]}


def run(mail: Mail, samples: int = 8) -> int:
    before = _timed("list_mailboxes", lambda: mail.list_mailboxes())
    roles: dict[str, int] = {}
    for m in before["mailboxes"]:
        roles[m["role"]] = roles.get(m["role"], 0) + 1
    print(f" — {len(before['mailboxes'])} mailboxes, roles {dict(sorted(roles.items()))}, {len(before['addresses'])} addresses")
    unseen_before = {m["name"]: m["unseen"] for m in before["mailboxes"]}

    month_ago = (datetime.now(UTC) - timedelta(days=30)).date().isoformat()
    queries: list[tuple[str, dict[str, Any]]] = [
        ("search newest", {"limit": 20}),
        ("search last 30 days", {"since": month_ago, "limit": 50}),
        ("search unread", {"unread": True, "limit": 10}),
        ("search with attachments", {"has_attachment": True, "limit": 10}),
        ("search body text", {"text": "the", "limit": 10}),
        ("search all mail", {"mailbox": "all", "limit": 10}),
    ]
    ids: list[str] = []
    for label, args in queries:
        res = _timed(label, lambda a=args: mail.search(a))
        print(
            f" — {len(res['results'])} results, examined {res['examined']}, partial={res['partial']}, more={res['next_cursor'] is not None}"
        )
        ids.extend(r["id"] for r in res["results"])
        if res["next_cursor"]:
            nxt = _timed(f"{label} (page 2)", lambda a=args, c=res["next_cursor"]: mail.search({**a, "cursor": c}))
            print(f" — {len(nxt['results'])} results")
    ids = list(dict.fromkeys(ids))[:samples]

    attachment: tuple[str, str] | None = None
    for i, mid in enumerate(ids):
        msg = _timed(f"get_message #{i + 1}", lambda m=mid: mail.get_message(m))
        print(
            f" — {msg['size']} bytes, text {msg['text_length']} chars ({msg['body_format']}), "
            f"{len(msg['attachments'])} attachments, invite={'invite' in msg}, undecryptable={msg['undecryptable']}"
        )
        for a in msg["attachments"]:
            if attachment is None and (
                a["content_type"] in ("application/pdf", "image/png", "image/jpeg") or a["content_type"].startswith("text/")
            ):
                attachment = (mid, a["part"])
    for i, mid in enumerate(ids[:3]):
        th = _timed(f"get_thread #{i + 1}", lambda m=mid: mail.get_thread(m))
        print(f" — {len(th['messages'])} messages, heuristic={th['heuristic']}, partial={th['partial']}")
    if attachment:
        meta, payloads = _timed("get_attachment", lambda: mail.get_attachment(*attachment))
        print(f" — {meta['content_type']}, delivered as {meta['delivered_as']}, {sum(len(p['data']) for p in payloads)} bytes")

    unseen_after = _unseen(mail)
    changed = [n for n in unseen_before if unseen_after.get(n) != unseen_before[n]]
    if changed:
        print(f"FAIL: unread counts changed in {len(changed)} mailbox(es) — something set \\Seen (or new mail arrived)")
        return 1
    print(f"OK: unread counts unchanged in all {len(unseen_before)} mailboxes after reading {len(ids)} messages")
    return 0


def main() -> None:
    try:
        source = config.load_source()
    except ConfigError as exc:
        print(f"proton-mcp-smoke: {exc}", file=sys.stderr)
        sys.exit(2)
    bridge = Bridge(source)
    try:
        code = run(Mail(bridge))
    except MailError:
        code = 1
    finally:
        bridge.close()
    sys.exit(code)
