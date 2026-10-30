"""The MCP layer end to end: a real HTTP server, the SDK's own client."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import anyio
import httpx
import pytest
import uvicorn
from conftest import Env, fixture
from fakeimap import free_port
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from proton_mcp.server import INSTRUCTIONS, build_app

TOKEN = "test-token-0123456789abcdef"

EXPECTED = {
    # name: (readOnly, destructive, idempotent, openWorld)
    "list_mailboxes": (True, False, True, False),
    "search": (True, False, True, False),
    "get_message": (True, False, True, False),
    "get_thread": (True, False, True, False),
    "get_attachment": (True, False, True, False),
    "mark": (False, False, True, False),
    "move": (False, False, True, False),
    "label": (False, False, True, False),
    "folders": (False, True, False, False),
    "labels": (False, True, False, False),
    "draft_email": (False, False, False, False),
    "draft_reply": (False, False, False, False),
    "draft_forward": (False, False, False, False),
    "draft_invite_response": (False, False, False, False),
    "update_draft": (False, True, False, False),
    "discard_draft": (False, True, True, False),
    "respond_to_invite": (False, True, False, True),
}


class Running:
    def __init__(self, port: int) -> None:
        self.base = f"http://127.0.0.1:{port}"


@pytest.fixture()
def server(env: Env) -> Iterator[Running]:
    env.store.add("INBOX", fixture("related-cid.eml"), 1_790_000_000)
    env.store.add("INBOX", fixture("reply-thread.eml"), 1_790_100_000)
    env.store.add(
        "Sent",
        b"From: me@example.com\r\nTo: pat@example.org\r\nSubject: Re: Budget 2027\r\nMessage-ID: <reply-2@example.com>\r\nIn-Reply-To: <reply-1@example.org>\r\n\r\nmine\r\n",
        1_790_050_000,
    )
    port = free_port()
    config = uvicorn.Config(build_app(TOKEN, env.bridge, env.mail), host="127.0.0.1", port=port, log_level="error", lifespan="on")
    srv = uvicorn.Server(config)
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(200):
        if srv.started:
            break
        time.sleep(0.02)
    yield Running(port)
    srv.should_exit = True
    t.join(5)


def call(base: str, fn: Any) -> Any:
    async def go() -> Any:
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30) as http:
            async with streamable_http_client(f"{base}/mcp", http_client=http) as (read, write, _):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    return await fn(session, init)

    return anyio.run(go)


def test_tools_list_shape_and_annotations(server: Running) -> None:
    async def fn(s: ClientSession, init: types.InitializeResult) -> Any:
        return init, await s.list_tools()

    init, listed = call(server.base, fn)
    assert init.instructions == INSTRUCTIONS and "untrusted" in init.instructions
    tools = {t.name: t for t in listed.tools}
    assert set(tools) == set(EXPECTED)
    for name, (ro, destructive, idem, open_world) in EXPECTED.items():
        a = tools[name].annotations
        assert (a.readOnlyHint, a.destructiveHint, a.idempotentHint, a.openWorldHint) == (ro, destructive, idem, open_world), name
        assert tools[name].inputSchema["additionalProperties"] is False
        assert tools[name].description and len(tools[name].description) > 40


def test_round_trip_search_message_thread(server: Running) -> None:
    async def fn(s: ClientSession, _: Any) -> Any:
        found = await s.call_tool("search", {"subject": "budget"})
        mid = found.structuredContent["results"][0]["id"]
        msg = await s.call_tool("get_message", {"id": mid})
        thread = await s.call_tool("get_thread", {"id": mid})
        trip = (await s.call_tool("search", {"has_attachment": True})).structuredContent["results"][0]["id"]
        pdf = await s.call_tool("get_attachment", {"id": trip, "part": "2"})
        img = await s.call_tool("get_attachment", {"id": trip, "part": "1.2"})
        return found, msg, thread, pdf, img

    found, msg, thread, pdf, img = call(server.base, fn)
    assert not found.isError and json.loads(found.content[0].text) == found.structuredContent
    m = msg.structuredContent
    assert m["untrusted"]["headers"]["subject"] == "Re: Budget 2027" and "Numbers look fine" in m["untrusted"]["text"]
    assert [x["untrusted"]["snippet"] for x in thread.structuredContent["messages"]][0] == "mine"
    res = [c for c in pdf.content if c.type == "resource"]
    assert res and res[0].resource.mimeType == "application/pdf" and res[0].resource.blob
    assert pdf.structuredContent["delivered_as"] == "pdf"
    images = [c for c in img.content if c.type == "image"]
    assert images and images[0].mimeType == "image/png"


def test_errors_are_typed(server: Running) -> None:
    async def fn(s: ClientSession, _: Any) -> Any:
        return (
            await s.call_tool("get_message", {"id": "m1.bogus"}),
            await s.call_tool("search", {"limit": 500}),
            await s.call_tool("search", {"nonsense": 1}),
            await s.call_tool("no_such_tool", {}),
            await s.call_tool("move", {"ids": ["m1.x"], "to": "archive"}),
        )

    bad_id, too_many, unknown_arg, unknown_tool, bad_move = call(server.base, fn)
    assert bad_id.isError and bad_id.structuredContent == {"error": "invalid_id", "message": "not a message id from this server"}
    assert too_many.isError and unknown_arg.isError and unknown_tool.isError
    assert bad_move.isError and bad_move.structuredContent["error"] == "invalid_id"


def test_bearer_auth(server: Running) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    hdrs = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    with httpx.Client(timeout=10) as c:
        assert c.post(f"{server.base}/mcp", json=body, headers=hdrs).status_code == 401
        r = c.post(f"{server.base}/mcp", json=body, headers={**hdrs, "Authorization": "Bearer wrong"})
        assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
        r = c.post(f"{server.base}/mcp", json=body, headers={**hdrs, "Authorization": f"bearer {TOKEN}"})
        assert r.status_code == 401  # exact scheme and token only
        assert c.get(f"{server.base}/other").status_code == 401
        r = c.post(
            f"{server.base}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
            },
            headers={**hdrs, "Authorization": f"Bearer {TOKEN}"},
        )
        assert r.status_code == 200 and r.json()["result"]["serverInfo"]["name"] == "proton-bridge-mcp"


def test_healthz(server: Running, env: Env) -> None:
    with httpx.Client(timeout=10) as c:
        r = c.get(f"{server.base}/healthz")
        assert r.status_code == 200 and r.text == "ok"
        env.creds.doc["accounts"][0]["state"] = "signed-out"
        r = c.get(f"{server.base}/healthz")
        assert r.status_code == 503 and r.text == "unavailable: bridge_unavailable"
        assert "@" not in r.text
