"""Timings on a seeded gluon. Opt-in (PROTON_MCP_PERF=1, plus PROTON_MCP_GLUON):
seeds PROTON_MCP_PERF_N messages (default 3000) over three years in three
folders, then times the tools and, for comparison, the raw SEARCH keys this
server avoids. Prints a table; bounds are loose on purpose."""

from __future__ import annotations

import os
import random
import time
from collections.abc import Iterator

import pytest
from conftest import CredsServer, creds_doc
from test_gluon import ADDRS, Gluon, append, start_gluon

from proton_mcp.credentials import EndpointSource
from proton_mcp.imapconn import Bridge
from proton_mcp.messages import DateCache
from proton_mcp.service import Mail

pytestmark = pytest.mark.perf
if not (os.environ.get("PROTON_MCP_PERF") and os.environ.get("PROTON_MCP_GLUON")):
    pytest.skip("set PROTON_MCP_PERF=1 and PROTON_MCP_GLUON to run", allow_module_level=True)

N = int(os.environ.get("PROTON_MCP_PERF_N", "3000"))
NOW = 1_793_000_000
WORDS = "invoice meeting budget report travel family project update review contract payment schedule".split()
FILLER = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor".split()
RESULTS: list[tuple[str, float, str]] = []


def message(i: int, rng: random.Random, refs: str = "") -> bytes:
    sender = f"sender{rng.randrange(400)}@example.org"
    subject = f"{rng.choice(WORDS).title()} {rng.choice(WORDS)} #{i}"
    words = " ".join(rng.choice(FILLER + WORDS) for _ in range(1200))
    if i % 997 == 0:
        words += " zanzibar"
    html = f"<html><body><div style='font-family:sans-serif'><p>{words}</p><p><a href='https://example.org/{i}'>link</a></p></div></body></html>"
    head = (
        f"From: Sender {i % 400} <{sender}>\r\nTo: user1@example.com\r\nSubject: {subject}\r\n"
        f"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <perf-{i}@example.org>\r\n{refs}"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    )
    return head.encode() + html.encode()


@pytest.fixture(scope="module")
def seeded(tmp_path_factory: pytest.TempPathFactory, certs: dict) -> Iterator[Gluon]:
    g = start_gluon(tmp_path_factory.mktemp("perf"), certs["bridge"])
    conn = g.raw()
    rng = random.Random(7)
    start = time.monotonic()
    for i in range(N):
        box = "INBOX" if i % 10 < 6 else "Archive" if i % 10 < 9 else "Sent"
        when = NOW - rng.randrange(3 * 365 * 86400)
        append(conn, box, message(i, rng), when, (), f"perf-{i}==")
    # one ten-message thread, spread over two months and three folders
    for k in range(10):
        refs = (
            ""
            if k == 0
            else f"In-Reply-To: <thread-{k - 1}@example.org>\r\nReferences: <thread-0@example.org> <thread-{k - 1}@example.org>\r\n"
        )
        raw = message(10_000 + k, rng, refs).replace(f"<perf-{10_000 + k}@".encode(), f"<thread-{k}@".encode())
        append(conn, ("INBOX", "Sent", "Archive")[k % 3], raw, NOW - 60 * 86400 + k * 6 * 86400, (), f"thread-{k}==")
    RESULTS.append((f"seed {N + 10} messages over IMAP APPEND", time.monotonic() - start, ""))
    conn.logout()
    yield g
    g.proc.terminate()
    g.proc.wait(10)
    print("\n\nperf on gluon", f"({N + 10} messages)")
    for name, secs, note in RESULTS:
        print(f"  {secs:8.2f}s  {name}  {note}")


@pytest.fixture()
def mail(seeded: Gluon, creds_server: CredsServer) -> Iterator[Mail]:
    doc = creds_doc(seeded.cert, seeded.port, 1, password="pass")
    doc["accounts"][0]["addresses"] = list(ADDRS)
    creds_server.doc = doc
    bridge = Bridge(EndpointSource(f"http://127.0.0.1:{creds_server.server_address[1]}/v1/account"), sleep=lambda s: None)
    yield Mail(bridge, CACHE)
    bridge.close()


CACHE = DateCache()


def timed(name: str, fn, note=lambda r: "") -> object:
    start = time.monotonic()
    result = fn()
    RESULTS.append((name, time.monotonic() - start, note(result)))
    return result


def test_search_paths(mail: Mail) -> None:
    r = timed(
        "search newest 20 (cold: dates fetched)", lambda: mail.search({"limit": 20}), lambda r: f"{len(r['results'])} results"
    )
    assert len(r["results"]) == 20
    timed("search newest 20 (warm)", lambda: mail.search({"limit": 20}))
    timed("search page 2", lambda: mail.search({"limit": 20, "cursor": r["next_cursor"]}))
    timed(
        "search from= one sender (all years)",
        lambda: mail.search({"from": "sender123@example.org", "limit": 50}),
        lambda r: f"{len(r['results'])} results, partial={r['partial']}",
    )
    timed(
        "search subject words",
        lambda: mail.search({"subject": "invoice budget", "limit": 20}),
        lambda r: f"{len(r['results'])} results",
    )
    timed(
        "search since 30 days",
        lambda: mail.search({"since": "2026-10-01", "limit": 50}),
        lambda r: f"{len(r['results'])} results",
    )
    rare = timed(
        "search body word (rare: every 997th)",
        lambda: mail.search({"text": "zanzibar", "limit": 5}),
        lambda r: f"{len(r['results'])} results, examined {r['examined']}, partial={r['partial']}",
    )
    assert rare["results"]


def test_thread_and_message(mail: Mail) -> None:
    hit = mail.search({"subject": "#10005", "limit": 1})["results"][0]
    th = timed(
        "get_thread (10 messages, 3 folders)", lambda: mail.get_thread(hit["id"]), lambda r: f"{len(r['messages'])} messages"
    )
    assert len(th["messages"]) == 10
    timed("get_message (~8 KB HTML)", lambda: mail.get_message(hit["id"]))


def test_raw_search_costs_the_design_avoids(seeded: Gluon) -> None:
    conn = seeded.raw()
    conn.select_folder("INBOX", readonly=True)
    timed("raw UID SEARCH UNDELETED (flags only)", lambda: conn.search(["UNDELETED"]))
    timed("raw UID SEARCH SINCE (date: a DB read per message)", lambda: conn.search(["SINCE", "1-Jan-2026"]))
    timed("raw UID SEARCH BODY (decrypts every message)", lambda: conn.search(["BODY", "zanzibar"]))
    timed(
        "raw UID SEARCH HEADER Message-ID (decrypts every message)",
        lambda: conn.search(["HEADER", "Message-ID", "thread-3@example.org"]),
    )
    uids = conn.search(["ALL"])
    timed(f"raw FETCH ENVELOPE x{len(uids)} (database only)", lambda: conn.fetch(uids, ["ENVELOPE"]))
    timed(f"raw FETCH INTERNALDATE x{len(uids)}", lambda: conn.fetch(uids, ["INTERNALDATE"]))
    conn.logout()
