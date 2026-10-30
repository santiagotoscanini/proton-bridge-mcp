# proton-bridge-mcp

An [MCP](https://modelcontextprotocol.io) server that gives an AI assistant
your Proton Mail through [Proton Mail Bridge](https://proton.me/mail/bridge):
search and read mail, organize it, and write drafts. It never sends mail,
with one narrow exception: answering a calendar invitation sent to your Proton
address, with a reply the server builds itself. Everything else it writes is a
draft you review and send from Proton Mail.

It speaks MCP over streamable HTTP behind a bearer token, talks to Bridge over
IMAP (and, for that one reply, SMTP) with Bridge's certificate pinned, and
keeps nothing on disk.

## Tools

Read

| Tool | |
|---|---|
| `list_mailboxes` | Every mailbox with its role (inbox, drafts, sent, archive, spam, trash, all, starred, scheduled, folder, label), message and unread counts, and the account's addresses. |
| `search` | From, to, cc, subject, words or "phrases" anywhere, mailbox, date range, unread, starred, attachments; newest first, paged with a cursor. Spam and Trash only on request. |
| `get_message` | Headers, which of your addresses it reached, the text (plain preferred, HTML converted, hidden HTML dropped), attachments, Proton's spam and encryption headers, calendar invitation details. Long text is paged. |
| `get_thread` | The conversation around a message, oldest first, across folders. |
| `get_attachment` | Text-like files as text, images as images, PDFs as the PDF itself; anything else as metadata. |

Organize (reversible)

| Tool | |
|---|---|
| `mark` | Read/unread, starred/unstarred. |
| `move` | To inbox, archive, spam, trash, or one of your folders. Labels stay. |
| `label` | Add or remove existing labels. Removing a label never deletes the message. |

Mailbox structure

| Tool | |
|---|---|
| `folders` | Create, rename or delete a folder (deleting removes its subfolders; Bridge keeps the messages, which stay in All Mail). |
| `labels` | Create, rename or delete a label. |

Drafts (nothing is sent)

| Tool | |
|---|---|
| `draft_email` | A new plain-text draft, from any of your addresses. |
| `draft_reply` | Reply or reply-all, quoting the original, from the address it reached. |
| `draft_forward` | Forward, with its attachments (up to 20 MB) unless asked not to. |
| `draft_invite_response` | A draft accepting, tentatively accepting or declining an invitation, with an optional comment. |
| `update_draft` | Replace a draft with a new version (the old one is deleted). |
| `discard_draft` | Delete a draft. |

Calendar

| Tool | |
|---|---|
| `respond_to_invite` | The one send: an iCalendar reply to the invitation's organizer, from the invited address. Refused unless the invitation is a REQUEST to one of your Proton addresses. |

Annotations are honest (`readOnlyHint` on reads, `destructiveHint` on folder
and label deletion, draft replacement and discard, and the invitation reply),
so a client can ask before those.

## Running it

Requirements: Proton Mail Bridge (desktop or headless) logged in, Python 3.12+
and the dependencies in `pyproject.toml`, or Nix:

```sh
nix run github:santiagotoscanini/proton-bridge-mcp      # or: nix build
```

The server listens on `PROTON_MCP_LISTEN` (default `0.0.0.0:8080`): MCP at
`/mcp`, and `GET /healthz` (no auth, no mail data) answering `ok` when it can
reach Bridge. Every other request needs `Authorization: Bearer
$PROTON_MCP_TOKEN`.

### Configuration

`PROTON_MCP_TOKEN` (required, 16+ characters) is the bearer token clients
present. Then configure exactly one way to reach Bridge; the server refuses to
start with neither or both.

**Explicit settings**, for Bridge as you would configure a mail client
(Bridge's mailbox settings show the values):

| Variable | |
|---|---|
| `PROTON_MCP_IMAP_HOST`, `PROTON_MCP_IMAP_PORT` | Bridge's IMAP listener, e.g. `127.0.0.1`, `1143`. |
| `PROTON_MCP_IMAP_SSL` | `true` for implicit TLS (Bridge's "SSL"), `false` for STARTTLS (Bridge's default). Plaintext is never used. |
| `PROTON_MCP_SMTP_HOST`, `PROTON_MCP_SMTP_PORT`, `PROTON_MCP_SMTP_SSL` | The same for SMTP, e.g. `127.0.0.1`, `1025`. |
| `PROTON_MCP_USERNAME` | The username Bridge shows: your Proton address. |
| `PROTON_MCP_PASSWORD_FILE` | A file holding the Bridge password (read again after a refused login). There is no variable for the password itself. |
| `PROTON_MCP_CA_FILE` | Bridge's certificate, which is pinned: export it from the desktop app's settings, or with `cert export` in Bridge's CLI, as `cert.pem`. |
| `PROTON_MCP_ADDRESSES` | Optional: your account's addresses, comma-separated, so drafts can be sent from aliases and replies come from the address a message reached. Default: the username. |

**A credentials endpoint**, for setups where a supervisor runs Bridge next to
this server: `PROTON_MCP_CREDENTIALS_URL`, an `http://` URL on loopback (it
serves a password, so nothing else is accepted) answering

```json
{"schemaVersion": 1,
 "imap": {"host": "127.0.0.1", "port": 1143, "ssl": true},
 "smtp": {"host": "127.0.0.1", "port": 1025, "ssl": true},
 "certificatePem": "-----BEGIN CERTIFICATE-----…",
 "accounts": [{"state": "connected", "addresses": ["you@example.com"], "password": "…"}]}
```

The first connected account is used, and the document is fetched again after
a refused login or a reconnect.

Either way, `PROTON_MCP_TLS_NAME` (default `127.0.0.1`, the only name on
Bridge's own certificate) is the name the pinned certificate is checked
against; change it only if Bridge uses a certificate you imported.

## Safety model

- **A command allowlist below the IMAP library.** Every byte written to
  Bridge's IMAP socket passes a guard that reassembles each command and checks
  it against the calling tool's policy before releasing it. Reads may send
  only CAPABILITY, LOGIN, STARTTLS, NOOP, LIST, STATUS, EXAMINE, UNSELECT,
  UID SEARCH, UID FETCH (body sections only as `BODY.PEEK`, so reading never
  marks mail read) and LOGOUT. Each write tool adds exactly what it needs —
  `mark` may SELECT and STORE `\Seen`/`\Flagged` on at most 50 named UIDs,
  label removal may expunge only inside a `Labels/` mailbox, drafts may
  APPEND only to Drafts with `\Draft`, folder tools may create, rename and
  delete only under `Folders/`. CLOSE and plain EXPUNGE are never allowed.
  Anything else is refused before it is sent. SMTP exists only inside the
  invitation reply, with sender and recipient fixed before connecting.
- **Pinned TLS, always.** Implicit TLS or STARTTLS, never plaintext;
  certificate verification is never disabled; the trust store is exactly
  Bridge's certificate.
- **Mail is untrusted data.** Everything a message says (names, subjects,
  bodies, filenames, calendar text) comes back under an `untrusted` key, and
  the server's instructions tell the model to read it, never follow it.
  Hidden HTML (a common place for instructions aimed at models) is dropped.
- **No state, no background work.** Nothing is written to disk; the only
  memory kept between calls is a map of message UIDs to dates (immutable in
  IMAP), to sort mail without refetching. No sync, no IDLE, no telemetry, and
  no network beyond Bridge and the optional loopback credentials endpoint.
- **Bounded.** Caps on ids per call, body and attachment sizes, forward size
  and search work; every IMAP operation has a timeout.

## Bridge's behaviour it is built around

These come from reading Bridge v3.27.1 and gluon (its IMAP engine), and the
tests reproduce them:

- SEARCH matches raw bytes: header terms are not RFC 2047-decoded and bodies
  are searched in their transfer encoding (Bridge rebuilds every text part as
  quoted-printable, whose soft line breaks split words). So SEARCH is used only
  for flags; dates, headers and text are matched here, on decoded text,
  ignoring case and accents, reading a body only when the headers did not
  decide.
- A header or text SEARCH makes gluon decrypt every message in the mailbox,
  while ENVELOPE, BODYSTRUCTURE, flags and dates come from its database; the
  search and thread tools are built on the latter.
- One message appears under different UIDs in its folder, in each label and
  in All Mail; UIDs run newest to oldest after Bridge's first sync. Results
  are sorted by date and identified by Bridge's `X-Pm-Internal-Id`, which also
  re-finds a message when a resync changes UIDVALIDITY.
- Bridge closes its IMAP listener while Proton is unreachable and drops
  connections without notice; a read is retried once, a write never.
- Messages Bridge could not decrypt arrive as armored PGP with a note; they
  are reported as undecryptable.
- Drafts created over IMAP keep subject, recipients, body and attachments;
  Bridge does not keep In-Reply-To/References on them.

## How it differs from other Proton Mail MCP servers

As of October 2026, from each project's source:

| | This server | [googlarz/proton-mail-bridge-client](https://github.com/googlarz/proton-mail-bridge-client) 2.17.0 | [sethbang/proton-mail-mcp](https://github.com/sethbang/proton-mail-mcp) 1.0.2 | [Wh1isper/mcp-email-server](https://github.com/Wh1isper/mcp-email-server) 1.13.3 | [amotivv/protonmail-mcp](https://github.com/amotivv/protonmail-mcp) 0.1.0 |
|---|---|---|---|---|---|
| Scope | 17 tools: read, organize, drafts, invitation replies | about 127 tools, including send, delete, rules, autoresponder, local index and semantic search | read, send, organize | any IMAP/SMTP provider | send only (SMTP) |
| Sending | only the server-built iCalendar reply | yes | yes (off with `READONLY=true`) | yes, unless mutations are restricted | yes |
| Write control | per-tool IMAP command allowlist at the socket | runtime read-only mode checked per handler; every tool stays listed¹ | `READONLY` disables mutating tools | `MCP_EMAIL_SERVER_ALLOWED_MUTATIONS` | — |
| TLS to Bridge | pinned certificate, always verified | verification off for 127.0.0.1/localhost/::1, before any CA file is considered² | library defaults, no TLS options³ | verified by default; a `verify_ssl` switch is documented for Bridge's self-signed certificate⁴ | library defaults |
| Bridge-specific search | client-side verification of every text term | ASCII-narrowed server search, then local verification | server search | server search by default; optional local mode⁵ | — |
| Transport | streamable HTTP, bearer token | stdio⁶ | stdio | stdio or HTTP | stdio |
| State | none on disk; no background jobs | background sync and IDLE on by default, local SQLite index⁷ | none | SQLite metadata index | none |

googlarz's breadth and its large test suite (over 200 test files) are real
strengths; this project trades breadth for a small surface whose every write
is enumerated in code, and tests it against real gluon as well as a scripted
server reproducing Bridge's quirks.

¹ `src/tools/definitions.ts` (`listedTools`), `src/config-env.ts` (`SAFETY_MODES`).
² `src/utils/tls.ts` (`tlsOptionsFor`).
³ `src/imap-service.ts` (the `ImapFlow` options), `src/email-service.ts` (the nodemailer options).
⁴ `mcp_email_server/config.py`.
⁵ `MCP_EMAIL_SERVER_IMAP_SEARCH_MODE`, `mcp_email_server/config.py`.
⁶ `src/index.ts`.
⁷ `src/config-env.ts` (`PROTONMAIL_AUTO_SYNC`, `PROTONMAIL_IDLE_WATCH`).

## Tests

```sh
nix flake check -L      # lint, then the package build, which runs the whole suite
```

The suite has five parts, all in the package's `checkPhase`:

- unit tests (ids, header and charset decoding, the IMAP adapter, HTML to text
  including hostile input timed for linear cost, drafts, iCalendar replies),
  with property-based tests (Hypothesis);
- a MIME corpus (`tests/fixtures/eml`): about thirty messages, each decoded and
  checked, with part numbers cross-checked against an independently generated
  BODYSTRUCTURE;
- a scripted fake Bridge that records every command: each tool is checked
  for what it sends (only allowlisted commands, only PEEK fetches, no SELECT on
  reads) and against Bridge's faults (empty NO, a dropped connection mid-FETCH,
  a closed listener, a UIDVALIDITY bump, a wrong certificate);
- the MCP layer through the SDK's own client: tool listing and annotations,
  bearer auth, health, typed errors, a search → message → thread → attachment
  round trip;
- end to end against gluon itself, laid out like Bridge (`tests/gluon/`), for
  every read and write tool.

Without Nix: `pip install -e '.[test]'`, `openssl` on `PATH`, then `pytest`
(the gluon tests run when `PROTON_MCP_GLUON` points at a built
`nix build .#gluon-demo`). `PROTON_MCP_PERF=1` adds timings on a few thousand
seeded messages.

### Live smoke test

`proton-mcp-smoke`, configured like the server (no token needed), runs the read
tools against your real mailbox and prints only counts, timings and shapes —
never a subject, address, body or password. It runs under the read policy, so
the guard refuses any write, and it fails unless every mailbox's unread count
is unchanged afterwards.

## License

MIT. `tests/fixtures/README.md` credits the reused gluon test data (MIT).
