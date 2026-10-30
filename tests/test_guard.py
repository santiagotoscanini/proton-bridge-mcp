"""The command guard on its own: every policy allows exactly what its tool
needs and nothing else, before anything reaches a socket."""

from __future__ import annotations

import pytest

from proton_mcp import service
from proton_mcp.errors import GuardViolation
from proton_mcp.guard import READ, CommandGuard, Policy, WireGuard, split_args
from proton_mcp.mailboxes import Mailboxes

BOXES = Mailboxes(
    [
        ((), "INBOX"),
        (("\\Drafts",), "Drafts"),
        (("\\Sent",), "Sent"),
        (("\\Archive",), "Archive"),
        (("\\Junk",), "Spam"),
        (("\\Trash",), "Trash"),
        (("\\All",), "All Mail"),
        (("\\Flagged",), "Starred"),
        (("\\Noselect",), "Folders"),
        (("\\Noselect",), "Labels"),
        ((), "Folders/Receipts"),
        ((), "Labels/Work"),
    ]
)


def ctx() -> service._Ctx:
    c = service._Ctx()
    c.boxes = BOXES
    return c


def guard(policy: Policy, selected: str | None = None, writable: bool = False) -> CommandGuard:
    g = CommandGuard()
    g.reset(policy)
    g.selected, g.writable = selected, writable
    return g


def ok(g: CommandGuard, name: str, *args: str, literal: bytes | None = None) -> None:
    g.check(name, args, literal)


def refused(g: CommandGuard, name: str, *args: str, literal: bytes | None = None) -> None:
    with pytest.raises(GuardViolation):
        g.check(name, args, literal)


READS = [
    ("CAPABILITY",),
    ("NOOP",),
    ("LOGOUT",),
    ("STARTTLS",),
    ("LOGIN", '"me@example.com"', '"secret"'),
    ("LIST", '""', '"*"'),
    ("STATUS", '"INBOX"', "(MESSAGES UNSEEN UIDVALIDITY UIDNEXT)"),
    ("EXAMINE", '"Folders/Receipts"'),
]


@pytest.mark.parametrize("cmd", READS)
def test_reads_are_always_allowed(cmd: tuple[str, ...]) -> None:
    ok(guard(READ), *cmd)


@pytest.mark.parametrize(
    "items",
    [
        "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE)",
        "(UID BODY.PEEK[])",
        "(UID BODY.PEEK[HEADER])",
        "(UID BODY.PEEK[1.2]<0.2048>)",
        "(UID BODY.PEEK[2.MIME])",
        "(UID BODY.PEEK[HEADER.FIELDS (X-PM-INTERNAL-ID REFERENCES)])",
        "(UID BODY.PEEK[3.HEADER.FIELDS.NOT (RECEIVED)])",
        "(UID BODY.PEEK[TEXT])",
    ],
)
def test_peek_fetches_allowed(items: str) -> None:
    ok(guard(READ, "INBOX"), "UID", "FETCH", "1:5,9", items)


@pytest.mark.parametrize(
    "items",
    [
        "(UID BODY[])",  # sets \Seen
        "(UID BODY[1])",
        "(RFC822)",
        "(RFC822.TEXT)",
        "(RFC822.HEADER)",
        "(UID BODY.PEEK[MIME])",  # MIME needs a part
        "(UID BODY.PEEK[HEADER.FIELDS ()])",
        "(UID BODY.PEEK[HEADER.FIELDS (A B)] BODY[TEXT])",
        "(UID BINARY.PEEK[1])",
        "(UID X-GM-LABELS)",
        "(UID FLAGS) ",
        "()",
    ],
)
def test_non_peek_and_unknown_fetch_items_refused(items: str) -> None:
    refused(guard(READ, "INBOX"), "UID", "FETCH", "1", items)


def test_fetch_and_search_need_an_open_mailbox() -> None:
    refused(guard(READ), "UID", "FETCH", "1", "(UID)")
    refused(guard(READ), "UID", "SEARCH", "ALL")


@pytest.mark.parametrize(
    "criteria",
    [
        "UNDELETED",
        "UNDELETED UNSEEN FLAGGED",
        "SINCE 1-Oct-2026 BEFORE 3-Oct-2026",
        "UID 1:100000 UNDELETED",
        'HEADER Message-ID "<a@example.com>"',
        'OR FROM "a" (TO "b" NOT SEEN)',
        "CHARSET UTF-8 ALL",
    ],
)
def test_search_grammar_allowed(criteria: str) -> None:
    ok(guard(READ, "INBOX"), "UID", "SEARCH", criteria)


@pytest.mark.parametrize("criteria", ["", "MODSEQ 5", "SINCE yesterday", "UID 1:*:3", "(ALL", 'X-GM-RAW "x"', "1:5"])
def test_search_grammar_refused(criteria: str) -> None:
    refused(guard(READ, "INBOX"), "UID", "SEARCH", criteria)


WRITES = [
    ("SELECT", '"INBOX"'),
    ("CLOSE",),
    ("EXPUNGE",),
    ("UID", "STORE", "1", "+FLAGS", "(\\Seen)"),
    ("UID", "COPY", "1", '"Labels/Work"'),
    ("UID", "MOVE", "1", '"Archive"'),
    ("UID", "EXPUNGE", "1"),
    ("CREATE", '"Folders/X"'),
    ("DELETE", '"Folders/Receipts"'),
    ("RENAME", '"Folders/Receipts"', '"Folders/Y"'),
    ("STORE", "1", "+FLAGS", "(\\Seen)"),
    ("COPY", "1", '"Trash"'),
    ("FETCH", "1", "(BODY.PEEK[])"),
    ("SEARCH", "ALL"),
    ("SUBSCRIBE", '"INBOX"'),
    ("ID", "NIL"),
    ("IDLE",),
    ("AUTHENTICATE", "PLAIN"),
]


@pytest.mark.parametrize("cmd", WRITES)
def test_read_policy_refuses_every_write(cmd: tuple[str, ...]) -> None:
    refused(guard(READ, "INBOX", writable=True), *cmd)


def test_append_refused_without_policy() -> None:
    refused(guard(READ), "APPEND", '"Drafts"', "(\\Draft \\Seen)", literal=b"x")


def test_crlf_injection_refused_everywhere() -> None:
    g = guard(READ, "INBOX")
    refused(g, "EXAMINE", '"INBOX"\r\nA1 DELETE "Folders/Receipts"')
    refused(g, "UID", "SEARCH", 'FROM "x\r\nA2 EXPUNGE"')
    refused(g, "LIST", '""', '"*"\n')
    refused(g, "LOGIN", '"me"', '"pw\x00"')


def test_mark_policy() -> None:
    p = service.mark_policy()
    g = guard(p)
    ok(g, "SELECT", '"INBOX"')
    for op in ("+FLAGS", "-FLAGS", "+FLAGS.SILENT", "-FLAGS.SILENT"):
        ok(g, "UID", "STORE", "1,3", op, "(\\Seen)")
        ok(g, "UID", "STORE", "1,3", op, "(\\Flagged)")
    refused(g, "UID", "STORE", "1", "+FLAGS", "(\\Deleted)")
    refused(g, "UID", "STORE", "1", "+FLAGS", "(\\Seen \\Deleted)")
    refused(g, "UID", "STORE", "1", "FLAGS", "(\\Seen)")  # replace-all
    refused(g, "UID", "STORE", "1", "+FLAGS", "(\\Draft)")
    refused(g, "UID", "STORE", "1:*", "+FLAGS", "(\\Seen)")  # open-ended set
    refused(g, "UID", "STORE", "1:51", "+FLAGS", "(\\Seen)")  # over 50 UIDs
    refused(g, "UID", "EXPUNGE", "1")
    refused(g, "UID", "MOVE", "1", '"Trash"')
    refused(g, "UID", "COPY", "1", '"Labels/Work"')
    refused(g, "APPEND", '"Drafts"', "(\\Draft)", literal=b"x")
    # STORE in a mailbox opened with EXAMINE is refused too.
    g2 = guard(p)
    ok(g2, "EXAMINE", '"INBOX"')
    refused(g2, "UID", "STORE", "1", "+FLAGS", "(\\Seen)")


def test_move_policy() -> None:
    g = guard(service.move_policy(ctx()))
    ok(g, "SELECT", '"INBOX"')
    for dest in ('"Archive"', '"Spam"', '"Trash"', '"INBOX"', '"Folders/Receipts"'):
        ok(g, "UID", "MOVE", "4", dest)
        ok(g, "UID", "COPY", "4", dest)
    for dest in ('"Sent"', '"Drafts"', '"All Mail"', '"Starred"', '"Labels/Work"', '"Folders/Nope"', '"Folders"'):
        refused(g, "UID", "MOVE", "4", dest)
    refused(g, "UID", "STORE", "4", "+FLAGS", "(\\Deleted)")
    refused(g, "UID", "EXPUNGE", "4")
    refused(g, "SELECT", '"Folders/Nope"')


def test_label_policy() -> None:
    g = guard(service.label_policy(ctx()))
    ok(g, "SELECT", '"INBOX"')
    ok(g, "UID", "COPY", "4", '"Labels/Work"')
    refused(g, "UID", "COPY", "4", '"Archive"')
    refused(g, "UID", "MOVE", "4", '"Labels/Work"')
    refused(g, "UID", "STORE", "4", "+FLAGS.SILENT", "(\\Deleted)")  # INBOX is not a label
    refused(g, "UID", "EXPUNGE", "4")
    ok(g, "SELECT", '"Labels/Work"')
    ok(g, "UID", "STORE", "4", "+FLAGS.SILENT", "(\\Deleted)")
    ok(g, "UID", "EXPUNGE", "4")
    refused(g, "UID", "STORE", "4", "+FLAGS.SILENT", "(\\Seen)")
    refused(g, "UID", "EXPUNGE", "1:*")


def test_structure_policies() -> None:
    g = guard(service.folders_policy())
    ok(g, "CREATE", '"Folders/Projects"')
    ok(g, "CREATE", '"Folders/Projects/2026"')
    ok(g, "RENAME", '"Folders/Projects"', '"Folders/Archive2"')
    ok(g, "DELETE", '"Folders/Projects"')
    for bad in ('"Folders"', '"Labels/X"', '"INBOX"', '"Trash"', '"Folders/"'):
        refused(g, "CREATE", bad)
        refused(g, "DELETE", bad)
    refused(g, "RENAME", '"Folders/A"', '"Labels/A"')
    refused(g, "SELECT", '"Folders/Projects"')
    lg = guard(service.labels_policy())
    ok(lg, "CREATE", '"Labels/Urgent"')
    refused(lg, "CREATE", '"Labels/A/B"')
    refused(lg, "DELETE", '"Folders/Receipts"')


def test_draft_policies() -> None:
    g = guard(service.draft_policy(ctx()))
    ok(g, "APPEND", '"Drafts"', "(\\Draft \\Seen)", literal=b"From: me@example.com\r\n\r\nx")
    ok(g, "APPEND", '"Drafts"', "(\\Draft)", literal=b"x")
    refused(g, "APPEND", '"INBOX"', "(\\Draft \\Seen)", literal=b"x")
    refused(g, "APPEND", '"Drafts"', "(\\Seen)", literal=b"x")  # must be a draft
    refused(g, "APPEND", '"Drafts"', "(\\Draft \\Flagged)", literal=b"x")
    refused(g, "APPEND", '"Drafts"', "(\\Draft)", literal=b"x" * (30 * 1024 * 1024 + 1))
    refused(g, "SELECT", '"Drafts"')
    refused(g, "UID", "EXPUNGE", "1")
    d = guard(service.discard_policy(ctx()))
    refused(d, "SELECT", '"INBOX"')
    ok(d, "SELECT", '"Drafts"')
    ok(d, "UID", "STORE", "7", "+FLAGS.SILENT", "(\\Deleted)")
    ok(d, "UID", "EXPUNGE", "7")
    refused(d, "APPEND", '"Drafts"', "(\\Draft)", literal=b"x")
    u = guard(service.replace_draft_policy(ctx()))
    ok(u, "APPEND", '"Drafts"', "(\\Draft \\Seen)", literal=b"x")
    ok(u, "SELECT", '"Drafts"')
    ok(u, "UID", "EXPUNGE", "7")
    refused(u, "SELECT", '"Trash"')


def test_unicode_mailbox_names_are_decoded_before_checks() -> None:
    g = guard(service.folders_policy())
    ok(g, "CREATE", '"Folders/&AMk-t&AOk-"')  # Folders/Été
    refused(g, "CREATE", '"&AMk-t&AOk-"')


def test_policies_declare_their_writes_only() -> None:
    assert READ.read_only
    assert not service.mark_policy().read_only
    assert service.mark_policy().append is None and service.mark_policy().expunge_in is None
    assert service.draft_policy(ctx()).select is None


# ── on the wire ──────────────────────────────────────────────────────────


def wire(policy: Policy = READ, selected: str | None = None, writable: bool = False) -> WireGuard:
    return WireGuard(guard(policy, selected, writable))


def test_split_args() -> None:
    assert split_args("FETCH 1:5 (UID BODY.PEEK[HEADER.FIELDS (A B)]<0.10>)") == [
        "FETCH",
        "1:5",
        "(UID BODY.PEEK[HEADER.FIELDS (A B)]<0.10>)",
    ]
    assert split_args('"a b" (x (y z)) atom') == ['"a b"', "(x (y z))", "atom"]
    for bad in ('"open', "(x", "x)", "BODY.PEEK[1"):
        with pytest.raises(ValueError):
            split_args(bad)


def test_wire_holds_bytes_until_a_line_is_complete_and_checked() -> None:
    w = wire(READ, "INBOX")
    assert w.feed(b"A1 UID SEARCH") == []  # imapclient writes a command in pieces
    assert w.feed(b" UNDELETED") == []
    assert w.feed(b"\r\n") == [b"A1 UID SEARCH UNDELETED\r\n"]
    assert w.feed(b"A2 NOOP\r\nA3 UID FETCH 4 (UID BODY.PEEK[1])\r\n") == [
        b"A2 NOOP\r\n",
        b"A3 UID FETCH 4 (UID BODY.PEEK[1])\r\n",
    ]


def test_wire_refuses_before_release() -> None:
    w = wire(READ, "INBOX")
    w.feed(b"A1 UID FETCH 4 (UID BODY[1])")
    with pytest.raises(GuardViolation):
        w.feed(b"\r\n")
    for line in (
        b"A1 CLOSE\r\n",
        b"A1 UID STORE 4 +FLAGS (\\Seen)\r\n",
        b"A1 EXPUNGE\r\n",
        b"DONE\r\n",
        b"\r\n",
        b"A1 NOOP\n",
        b"A1 NO\rOP\r\n",
    ):
        with pytest.raises(GuardViolation):
            wire(READ, "INBOX").feed(line)


def test_wire_literals() -> None:
    p = service.draft_policy(service._Ctx(BOXES))
    w = wire(p)
    out = w.feed(b'A1 APPEND "Drafts" (\\Draft \\Seen) {11}\r\n')
    assert out == [b'A1 APPEND "Drafts" (\\Draft \\Seen) {11}\r\n']
    assert w.feed(b"hello ") == [b"hello "]  # literal bytes pass through, never parsed as commands
    assert w.feed(b"A2 X\r") == [b"A2 X\r"]  # even command-like bytes, inside the literal
    assert w.feed(b"\r\n") == [b"\r\n"]
    # LITERAL+: the literal follows in the same write.
    w2 = wire(p)
    assert b"".join(w2.feed(b'A1 APPEND "Drafts" (\\Draft) {3+}\r\nabc\r\n')) == b'A1 APPEND "Drafts" (\\Draft) {3+}\r\nabc\r\n'
    # Nothing may follow a literal but CRLF: no smuggled second command.
    w3 = wire(p)
    w3.feed(b'A1 APPEND "Drafts" (\\Draft) {3}\r\nabc')
    with pytest.raises(GuardViolation):
        w3.feed(b' A2 DELETE "Folders/X"\r\n')
    with pytest.raises(GuardViolation):
        wire(p).feed(b'A1 APPEND "INBOX" (\\Draft) {3}\r\n')
    with pytest.raises(GuardViolation):
        wire(READ, "INBOX").feed(b"A1 UID SEARCH TEXT {3}\r\n")  # literals only for APPEND


def test_policies_hold_through_the_wire() -> None:
    w = wire(service.mark_policy())
    assert w.feed(b'A1 SELECT "INBOX"\r\n')
    assert w.feed(b"A2 UID STORE 4,7 +FLAGS.SILENT (\\Seen)\r\n")
    with pytest.raises(GuardViolation):
        w.feed(b"A3 UID STORE 4 +FLAGS (\\Deleted)\r\n")
