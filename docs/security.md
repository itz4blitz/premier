# Security model

Premier records what an agent did on your machine. A trace can contain
prompts, source code, command lines, and terminal output, so the tool is
built on the assumption that traces are sensitive.

This page states what each control does and where it stops.

## Summary

| Threat | Control | Limit |
| --- | --- | --- |
| A web page in your browser reads traces from the local viewer | Loopback bind, Host check, cross-origin check | Relies on the browser's `Host`, `Origin`, and `Sec-Fetch-Site` headers |
| Another machine reaches the viewer | Loopback by default; a non-loopback bind requires TLS, authentication, and encrypted traces | Trace encryption is checked at startup only |
| A proxy sees collector traffic | `premier emit` and the shell helper bypass proxies for a loopback collector | Other HTTP clients follow their own proxy rules |
| The recorded process forges the recorder's evidence | The collector rejects recorder-owned kinds and sources, restricts names to ASCII, and stamps every event with its own receipt time | The process can still assert any other event |
| Secrets end up in a trace | Redaction at record time (secret field names in payloads, header pairs, argument lists, and JSON strings; built-in value patterns; the run's collector token), repeated at export time | Pattern-based, and terminal output is stored as printed by default; see [redaction.md](redaction.md#what-this-does-not-catch) |
| Trace files are read from disk or a backup | Owner-only file permissions; optional encryption | The key file sits on the same machine |
| A trace is damaged or carelessly edited after recording | Event hash chain and manifest seal, checked by `premier verify` | An unsigned trace is only self-consistent: whoever can write to it can rebuild the chain and the seal |
| A trace is deliberately rewritten after recording | Optional Ed25519 signature, checked with `premier verify --public-key` | Only as good as the secrecy of the signing key, and only when the verifier supplies the key it expects |
| Recorded text drives the terminal that displays it | Control characters are escaped in the CLI's text output | JSON output is exact and not escaped |
| Trace content is sent to a model provider | Only through the local assistant, only when you ask it a question, after redaction; can be disabled | Redaction is best effort |

Premier does not defend against a hostile process running as your own user.
Such a process can read your trace files, read the collector token from the
recorded process's environment, and rewrite a trace directory.

## Files on disk

A trace is a directory. On Unix, the recorder creates its directories with
mode `0700` and the manifest and journal files with mode `0600`.

`premier export -o <file>` creates its output with mode `0600` on Unix,
whatever the umask. It is a plaintext copy of the trace, redacted but not
encrypted, also when the trace it was read from is encrypted; in that case
`export` prints a warning on stderr. Output redirected from stdout gets the
permissions of the redirection.

`premier keygen` creates the private signing key with mode `0600` and the
public key file with your default umask.

## The collector

`premier record` starts an HTTP collector for the recorded process
([collector.md](collector.md)).

- It binds `127.0.0.1` on a port chosen by the OS. It is not reachable from
  another machine and cannot be configured to be.
- It is plain HTTP.
- Every recording gets a new bearer token: 256 bits from the system random
  number generator, unrelated to the trace and event ids (which are
  time-ordered and stored in the trace). The token is passed to the
  recorded command in `PREMIER_COLLECTOR_TOKEN`, is compared in constant time,
  and stops working when the recording ends. The collector URL, without the
  token, is stored in the trace's `session.start` event. The recorder
  replaces the token's value wherever it would be stored (terminal output,
  payloads, event fields, the command line), so a command that prints its
  environment does not leave it in the trace; the manifest notes this as
  `redaction.implicit_rules: ["collector-token"]`.
- Request bodies are limited to 2 MiB (`413` above that) and must arrive
  within 10 seconds (`408`). There is no rate limit on accepted requests.
- A request without the token gets its `401` after a delay that grows with
  each refusal in a row (100 ms steps, at most 1 second), and the first one
  of a recording is written to the trace as a `collector.unauthorized` event.
  The delay is not what keeps a guesser out, the size of the token is; it
  bounds what a process hammering the collector costs the recorder.
- When the recorded command has exited, requests in flight get 2 seconds to
  finish and are then dropped, so a client that holds a connection open
  cannot keep a recording from being finalized.

What the token protects: a local process that does not have it cannot append
events. What it does not protect: anything that can read the recorded
process's environment has the token.

**Recorder-owned evidence.** The recorded process holds the token, so it could
otherwise write its own exit status or terminal output. The collector rejects
(`422`) the kinds `session.start`, `session.interrupted`, and `process.*`, and
the sources `premier`, `command`, `process`, `recorder`, `premier-recovery`,
and `adapter.*`.

**Field validation.** So that a client cannot send something that merely
looks like a recorder-owned name, `kind`, `source`, and `actor_type` are
limited to ASCII letters, digits, `.`, `_`, `:`, and `-` (at most 128 bytes):
no zero-width space inside `process.exit`, no look-alike letter. The other
identity fields (`actor_id`, span and correlation ids, `status`,
`parent_event_id`, `links`) may hold any Unicode up to 256 bytes but no
control characters, so they cannot carry escape sequences or line breaks into
a terminal or a log. Violations are rejected with `400`. The rules are listed
in [collector.md](collector.md#field-rules).

**Timestamps.** The `timestamp` of a collector event is always the recorder's
receipt time. A producer cannot back-date or forward-date an event; the time
it claims is kept as `payload.producer_timestamp` and is only a claim.

Everything else that passes validation is accepted as sent. An
`approval.decision` with `actor_type: "human"`, a `tool.result` with status
`ok`, a model's token usage: these are claims made by the instrumented
process. Premier stores them and labels their `source`; it does not check
them against anything.

**Proxies.** `premier emit` and `sdk/shell/premier-emit.sh` ignore
`HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` when the collector URL is
loopback (`localhost`, a `.localhost` name, `127.0.0.0/8`, `::1`), so the
token and payload are not routed through a proxy. For a non-loopback URL they
use the environment's proxy settings.

## The viewer server

`premier open`, `premier serve`, and `premier record --open` run the viewer
server. It serves the viewer UI and a read-only JSON API over the traces in
one directory. The only API call that does more than read is the
[local assistant](#the-local-assistant).

The default bind is `127.0.0.1:4317`, with no authentication. In that mode
whoever can reach the port on loopback is treated as the local user.

`premier open <trace>` and `record --open` serve that single trace. Other
traces in the same directory are not listed and cannot be fetched by id.

The API does not tell clients where the server keeps its traces. The recover
hint for an abandoned trace names the trace directory only
(`premier recover --force abandoned.atrace`), a lookup against a trace
directory that does not exist answers `404`, and one that cannot be read
answers `500` with a fixed message while the path goes to the server log. The
routes and their fields are listed in [cli.md](cli.md#the-viewer-api).

An encrypted trace the server has no key for is reported as `locked`, not as
damaged, with only the public part of its manifest. See
[Encryption at rest](#encryption-at-rest).

### Host and cross-origin guard

Two checks run before authentication.

**Host check.** When no credentials are configured, the request's `Host` must
be `localhost` or a loopback IP address (any port). Anything else gets `403`,
on every route including the static UI. A request with more than one `Host`
header, or an unparsable one, also gets `403`.

Without this, a web page whose DNS name is re-pointed at `127.0.0.1` (DNS
rebinding) would be same-origin with the viewer and could read every trace.

**Cross-origin check.** On every `/api/` route, with or without credentials:

- If the request has `Sec-Fetch-Site`, it must be `same-origin` or `none`.
- Otherwise, if it has `Origin`, the origin's host and port must equal the
  request's `Host`. `Origin: null` is refused.
- A request with neither header is not from a browser and is allowed.

Refused requests get `403`. The server sends no CORS headers, so a
cross-origin page could not read a response anyway; the check also stops the
request from having an effect, which matters for the assistant endpoint.

Every response also carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store`, and a Content-Security-Policy that limits scripts,
styles, images, and connections to the server's own origin.

### Authentication and scopes

`premier serve` accepts two kinds of credential. When either is configured,
every route requires one, including the static UI and `/api/health`.
Unauthenticated requests get `401`.

**Password** (`--password` or `PREMIER_PASSWORD`). HTTP Basic. The username is
ignored and the password is compared in constant time. A blank password
counts as not configured. A password login acts as the local user: tenant
`local`, with both scopes. Prefer the environment variable; a `--password`
argument is visible in the process list.

The password is one secret shared by everyone who signs in: there are no
per-user accounts, and a sign-in is not attributed to a person. Use a long
random value. `serve` prints a warning when the password is shorter than 12
characters and the server listens on a non-loopback address; it does not
refuse to start.

**Wrong credentials.** A request that presents a wrong password or an unknown
bearer token is answered `401` after a delay: 250 ms for the first, 250 ms
more for each further refusal in a row, at most 2 seconds. A successful
sign-in resets it. The first five refusals in a row and every hundredth after
that are logged on the server (`refused password credentials for the viewer
(3 refused in a row)`). A request without credentials, such as a browser's
first, is answered at once and is not counted. There is no lockout: a
lockout on a shared secret would let anyone lock everyone out.

**Bearer tokens** (`--auth-config <file>` or `PREMIER_AUTH_CONFIG`). A JSON
file:

```json
{
  "tokens": [
    {
      "subject": "ci-reader",
      "tenant_id": "acme",
      "token_sha256": "<64 hex characters: SHA-256 of the token>",
      "scopes": ["trace:read"]
    }
  ]
}
```

- The file stores only the SHA-256 of each token. A client sends
  `Authorization: Bearer <token>`; the server hashes it and compares in
  constant time.
- On Unix the file must not be readable by group or others, or `serve`
  refuses to start. It must contain at least one token.
- `subject` is 1-128 ASCII letters, digits, `-`, `_`, `.`, or `@`.
  `tenant_id` is 1-128 ASCII letters, digits, `-`, `_`, or `.`: the same rule
  as `premier record --tenant` and `premier claim --tenant`, since a
  credential for a tenant no trace can carry would never read anything.
- `scopes` may contain `trace:read` and `assistant:use`. Any other value is an
  error. The default is no scopes.
- A `token_sha256` may appear once. Two entries with the same token would
  make the second unreachable, so `serve` refuses to start.
- `subject` names the holder of a token in the server log: with
  `RUST_LOG=debug` every authenticated bearer request logs its subject and
  tenant. It is not recorded anywhere else.

```sh
TOKEN=$(openssl rand -hex 32)
printf %s "$TOKEN" | shasum -a 256   # put the hex digest in token_sha256
curl -H "Authorization: Bearer $TOKEN" https://traces.example.internal:4317/api/traces
```

| Scope | Allows |
| --- | --- |
| `trace:read` | Listing traces, reading a trace's manifest and events, and following a live trace. |
| `assistant:use` | Asking the local assistant about a trace. |

A request without the needed scope gets `403`.

**Tenants.** Every trace has a `tenant_id` in its manifest, set by
`premier record --tenant` (default `local`) or `premier claim`. A principal
sees only traces whose tenant equals its own. Other traces are absent from
listings and return `404`.

The embedded viewer UI does not attach a bearer token to its requests. A
browser signs in with the password; bearer tokens are for API clients.
Because a password sign-in is the `local` identity, **the browser viewer
cannot show a trace owned by another tenant**. Such a trace is read through
the API with that tenant's token. `premier open <trace>` and
`record --open` refuse a tenant-owned trace with that explanation instead of
opening a viewer that would answer "not found".

### Non-loopback binds and TLS

`premier serve --bind <address>` on anything other than a loopback address
refuses to start unless all of these hold:

1. **TLS is configured**: `--tls-cert` and `--tls-key` (PEM), given together.
   On Unix the key file must not be readable by group or others.
2. **Authentication is configured**: a non-blank password or an auth config.
3. **Every trace in `--trace-dir` is encrypted** and decrypts with the key
   given by `--key-file` or `PREMIER_TRACE_KEY_FILE`. A plaintext trace, or
   one encrypted under a different key, stops startup with an error naming
   it.

The third check runs once, at startup. A plaintext trace copied into the
directory afterwards is served. Keep the served directory separate from the
directory you record into.

The Host check applies only to an unauthenticated server, so an authenticated
server can be reached by its DNS name. TLS is optional on loopback.

`premier open` has no authentication or TLS options and therefore only binds
loopback addresses.

## The local assistant

The viewer has an "Ask AI" panel. It answers questions about the open trace by
running an agent CLI that is already installed on the machine running
`premier`.

### What it runs

The first time the assistant panel is opened or asked (`GET /api/assistants`
or a question), unless the assistant is disabled, the server looks on `PATH`
for `claude`, `codex`, `grok`, and `gemini`, and runs `<cli> --help` (and
`codex exec --help`) to check that each one supports the flags below. Nothing
is run when the server starts, and a server whose assistant is never used
runs no CLI at all. Each probe has standard input closed and 5 seconds to
finish; a CLI that does not answer in that time is stopped and listed as
unavailable. The result is kept for the life of the process. A CLI
that is missing any required flag is listed as unavailable. `opencode` is
listed but never available, because it has no documented non-interactive
read-only mode.

**Codex gets a second check.** Accepting a flag is not the same as honouring
it, so for `codex` the server also asks the installed CLI for its effective
feature state under the same overrides the assistant invocation passes:

```sh
codex --config features.shell_tool=false --config features.unified_exec=false features list
```

with standard input closed. The output is read as one feature per line, the
first field being the feature name and the last its state. Codex is marked
unavailable unless:

- the command runs and exits successfully;
- a line for `shell_tool` exists and its last field is `false`;
- a line for `unified_exec` exists and its last field is `false`.

Those two are the features that give the model command execution. A feature
that is reported `true` with its override applied, or is not reported at all,
makes Codex unavailable, with a reason such as `installed Codex CLI does not
confirm that command execution is disabled (unified_exec is true with it
switched off)`. The probe checks nothing else: not other features, and not
the sandbox or approval settings beyond the presence of their flags in
`--help`.

When you submit a question, the server starts the chosen CLI once:

| CLI | Invocation |
| --- | --- |
| `claude` | `--print --output-format text --permission-mode dontAsk --tools "" --no-session-persistence --safe-mode <prompt>` |
| `codex` | `--ask-for-approval never exec --sandbox read-only --ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check --color never --config features.shell_tool=false --config features.unified_exec=false --config web_search="disabled" <prompt>` |
| `grok` | `--single <prompt> --permission-mode dontAsk --tools "" --no-subagents --no-memory --disable-web-search --max-turns 1 --verbatim` |
| `gemini` | `--prompt <prompt> --approval-mode plan --sandbox --output-format text --extensions none --allowed-mcp-server-names premier-none` |

### What leaves the machine

**The assistant sends trace content to the model provider behind the CLI you
choose**, using that CLI's own login or API key. Nothing is sent until you
submit a question.

The panel says so where the question is typed: it names the provider's vendor
("sends to Anthropic"), states what is sent, and keeps the Ask button disabled
until the box "Send redacted trace content to <vendor>" is ticked. The
agreement is per provider and lasts until the panel is closed. The text and
the box stay visible at every window size.

The prompt contains:

- a fixed instruction to treat trace content as untrusted data;
- the outcome of the run on its own: trace id, start and end time, exit
  code, termination, whether the trace is finalized, and its event and
  diagnostic counts (at most 1,000 characters), so that a long command line
  cannot push it out of the next item;
- the trace manifest (at most 4,000 characters);
- the selected event, if any (at most 8,000 characters);
- the newest events, up to 40 of them and 24,000 characters in total, each
  at most 6,000 characters. The budget is spent from the newest event
  backwards, so what does not fit is the oldest. The prompt names the
  sequence range it carries and how many earlier events it leaves out, and
  tells the model to say so when a question is about the whole run;
- the conversation so far in the panel (at most 12 messages and 12,000
  characters);
- your question (at most 6,000 characters).

Before it is assembled, the trace content is redacted with the
[`premier export`](redaction.md#premier-export) rules: secret field names
(as keys, header-style pairs, argument lists, and JSON inside strings) and
the built-in value patterns, applied to every string including terminal
output. Sections over their limit are cut and marked `…[truncated]`.

That redaction is pattern-based. Terminal output and payloads that contain a
secret with no recognisable name or shape reach the provider as recorded.
Apply the same judgement as you would before pasting a log into a chat
window.

### Confinement

- The CLI's working directory is a new, empty, owner-only temporary
  directory, removed afterwards. It is not the trace directory and not the
  directory `premier` was started from.
- Standard input is closed.
- `PREMIER_PASSWORD`, `PREMIER_AUTH_CONFIG`, `PREMIER_TLS_KEY`,
  `PREMIER_TRACE_KEY_FILE`, `PREMIER_SIGN_KEY_FILE`, `PREMIER_COLLECTOR_URL`,
  and `PREMIER_COLLECTOR_TOKEN` are removed from its environment.
- The flags above turn off tools, or restrict the CLI to read-only operation,
  and turn off session persistence where the CLI supports it.
- One request runs at a time; a second gets `429`. The CLI runs in its own
  process group, and the whole group is killed after 45 seconds or when the
  browser disconnects, so a wrapper's helper processes do not outlive the
  request. An answer over 64 KiB is discarded (`502`); diagnostics the CLI
  writes to standard error are kept only up to 64 KiB and never void an
  answer.
- The request body may be up to 160 KiB, which covers every request the
  character limits above allow, whatever the script.
- The endpoint requires the `assistant:use` scope and passes the Host and
  cross-origin checks like every other API route.

**Seeing what will be sent.** Under the consent checkbox the panel states
what the next question would send: the event range (`events #261–#300 (the
newest 40 of 300)`), the number of earlier messages, and the size of the
prompt, with a warning when earlier events are left out. **Show the exact
text** displays the prompt itself, question included. Both come from `POST
/api/traces/{trace}/assistant/preview`, which builds the prompt on the
Premier server exactly as a question would and runs no provider: nothing
leaves the machine to produce the preview. Every answer is followed by the
range it was based on (`Based on events #261–#300 …`), taken from the
`context` block the server returns with the answer, not from the model's
own account.

The conversation, the draft, the chosen provider and the consent given are
kept per trace for as long as the page is open, so closing the panel does not
discard them, and an answer that arrives after the panel was closed is there
when it is reopened. They are held in the page's memory only; a reload
clears them.

Limits of that confinement:

- It relies on each CLI honouring its own flags. Premier does not sandbox the
  process. It runs as your user, with your home directory and the rest of
  your environment.
- For `gemini`, plan mode is read-only and user extensions and MCP servers are
  disabled, but the CLI's built-in file and web tools remain available to the
  model.
- The prompt is passed as a command-line argument, so other local users can
  see it in the process list while the CLI runs.

### Turning it off

```sh
premier open --no-assistant
premier serve --no-assistant
PREMIER_DISABLE_ASSISTANT=1 premier record --open -- ./agent
```

`PREMIER_DISABLE_ASSISTANT` accepts any value other than empty, `0`, `false`,
`no`, or `off`, and applies to `open`, `serve`, and `record --open`. With the
assistant disabled no CLI is looked up or run, the provider list is empty, and
the assistant endpoint answers `404`.

On a shared `premier serve`, the assistant runs on the server, with the
server account's CLI credentials. Leave `assistant:use` out of a token's
scopes, or disable the assistant, unless that is intended.

## Encryption at rest

Encryption is off unless a key file is configured.

### Enabling it

Name a key file when recording, with the global `--key-file` option or the
`PREMIER_TRACE_KEY_FILE` variable:

```sh
( umask 077 && openssl rand -hex 32 > ~/.premier-trace.key )
premier --key-file ~/.premier-trace.key record -- ./agent run

# or
export PREMIER_TRACE_KEY_FILE=~/.premier-trace.key
premier record -- ./agent run
```

- **`--key-file`** is accepted by every subcommand, before or after the
  subcommand name. When both the option and the variable are given, the
  option wins.
- **Format.** A text file containing exactly 64 hexadecimal characters (a
  256-bit key). Leading and trailing whitespace is ignored. Anything else
  fails with `trace encryption key must be exactly 64 hexadecimal characters`.
- **Permissions.** On Unix the file must not be accessible by group or
  others. Otherwise every command that needs the key fails with
  `trace key file must not be accessible by group or other users`.

Every command that reads an encrypted trace needs the same key. Without it
`verify`, `sign`, `query`, `export`, `diff`, `replay`, `recover`, and `claim`
fail with `encrypted trace requires --key-file or PREMIER_TRACE_KEY_FILE`;
with a different key they fail with `trace decryption failed: wrong key`.

A trace that cannot be opened is still shown, as sealed rather than damaged:

- `premier list` prints it from the public part of its manifest, with the
  directory name in place of the encrypted run name, followed by
  `[encrypted: key required]` when no key file was configured, or
  `[encrypted: <reason>]` (for example `trace decryption failed: wrong key`)
  when the configured key does not open it.
- The viewer API reports `integrity: "locked"` with a detail that names
  `--key-file` and `PREMIER_TRACE_KEY_FILE`, and the trace list shows
  `Encrypted · key required` with a `Locked` badge. Its events cannot be
  read until the server is restarted with the right key. A manifest that is
  actually unreadable is still `invalid`.

### What is encrypted

A per-trace key is derived from the key file and the trace id with
HKDF-SHA256. Each event is encrypted separately with XChaCha20-Poly1305 and a
random nonce, and is bound to its trace id and sequence number. The sensitive
part of the manifest is encrypted the same way and bound to the trace id and
tenant.

Encrypted: every event; and from the manifest the run name, command line, end
time, exit status and termination, journal digest and event count,
diagnostics, capabilities, the redaction and adapter records, and the whole
seal (chain head, seal digest, and the signature with the signer's public
key).

### What stays readable on disk

```json
{
  "format_version": 2,
  "trace_id": "01a130a6-51e5-7a93-bfc3-9903396ca127",
  "tenant_id": "local",
  "name": null,
  "command": [],
  "started_at": "2026-10-12T15:06:08.744965Z",
  "ended_at": null,
  "exit_code": null,
  "journal": null,
  "capabilities": [],
  "encryption": {
    "algorithm": "XChaCha20-Poly1305",
    "key_id": "sha256:0b43dda5ae09892ebee1ead19613e0b4",
    "private_manifest": "xTkfQ82bFZJIprZ9..."
  }
}
```

- The trace id, tenant id, start time, and format version.
- `key_id`: the first 16 bytes of the SHA-256 of the key, used to tell a
  wrong key from tampering.
- File names, sizes, and modification times, and with them roughly how much
  was recorded and when.
- The size and sequence number of each event frame.
- `recorder.lease`, holding the recorder's process id and process start
  time, while recording.
- Whether the trace is signed is not visible: the seal is inside the
  encrypted part.

Other things to know:

- Encryption does not redact. Anyone with the key file reads everything.
- The key file is on the same machine as the traces. It protects copies of
  the trace directory (backups, synced folders, a shared server's disk), not
  a machine whose user account is compromised.
- The recorded command inherits `PREMIER_TRACE_KEY_FILE` (and
  `PREMIER_SIGN_KEY_FILE`) when they are set in the environment, and, running
  as you, can read the files they name. `--key-file` and `--sign-key` do not
  add those variables to the command's environment, but the paths are
  visible in the recorder's own command line and the files are still
  readable by your user.
- What you see in the terminal, and anything `premier export` writes, is
  plaintext. `export` says so on stderr when the trace is encrypted, and
  creates an `--output` file with mode `0600`.
- There is no command that turns an encrypted trace back into a plaintext
  trace. `premier export` produces a plaintext JSON copy.

### `premier encrypt`

```sh
premier encrypt run.atrace --new-key-file ~/.premier-trace.key
```

Encrypts a finalized plaintext trace, or re-encrypts an encrypted trace under
a new key (the current key is read from `--key-file` or
`PREMIER_TRACE_KEY_FILE`).

- The trace must be finalized and must pass verification. A trace that fails
  verification is refused, because re-sealing would write a fresh digest over
  whatever happened to decode. There is no `--allow-unverified`.
- Events are re-encrypted unchanged, so the event chain and its head are
  preserved. The journal digest and the encryption envelope change, and both
  are sealed fields, so the seal is recomputed.
- **An existing signature is dropped unless you re-sign.** It covered the old
  manifest. With `--sign-key` or `PREMIER_SIGN_KEY_FILE` the new seal is
  signed with that key (`re-sealed and signed with the configured signing
  key`). Without one, `encrypt` prints a warning that the previous signature
  covered the old manifest and was dropped, and that `premier sign` re-signs.
  `premier claim` handles a signature the same way, with the variable only.
  Re-signing is a statement by whoever holds that key at that moment, not by
  the original recorder.
- It refuses a trace that has files under `blobs/` or `indexes/`, since those
  would stay unencrypted.
- The encrypted copy is written beside the trace, read back, and compared
  event by event with the original before the two directories are swapped. If
  the swap fails the original is put back.
- The original directory is then deleted with an ordinary file removal. It is
  not securely wiped; on most filesystems the old plaintext blocks remain
  until overwritten.

## What verification proves

A trace written by this version (format version 2) carries three layers,
specified in [trace-format.md](trace-format.md):

1. **A journal digest and an event hash chain.** Every event names the hash
   of the event before it, starting from a value derived from the trace id.
2. **A manifest seal.** A digest over every manifest field, including the
   journal digest and the head of the event chain.
3. **An optional signature.** An Ed25519 signature over the seal, added by
   `premier record --sign-key`, `premier sign`, or `PREMIER_SIGN_KEY_FILE`.

`premier verify` checks all of them and words its result by what it could
establish (the exact lines are in [cli.md](cli.md#verify)):

| `premier verify` says | What was checked | What it is worth |
| --- | --- | --- |
| `verified: ... signed by the supplied key <fingerprint>` | Chain, seal, and a signature by the key you passed with `--public-key`. | Nobody without that private key changed any event or manifest field after signing. |
| `consistent: ... signed by an unknown key <fingerprint>` | Chain, seal, and a signature by the key stored in the trace itself. | The same as unsigned, until you compare the fingerprint with one you trust: someone rewriting the trace can sign it with a key of their own. |
| `consistent: ... unsigned` | Chain and seal. | The trace is self-consistent. See below. |
| `consistent (v1: digest only)` | A version 1 trace: the journal digest and event structure only. | The journal was not corrupted. Most manifest fields are covered by nothing. |

The viewer API reports the same levels as `integrity_protection`
(`signed`, `sealed`, `digest_only`) beside `integrity: "verified"`, and the
viewer labels them `signed by <fingerprint>`, `unsigned, self-consistent
only`, and `unsigned, v1 digest only`. The server has no list of trusted
keys, so its `signed` is the `signed by an unknown key` row above. `query`,
`export`, `diff`, `replay`, `encrypt`, and `sign` refuse a finalized trace
that fails verification.

### An unsigned trace is only self-consistent

Without a signature, verification detects any change that was not carried
through consistently:

- an edited, inserted, removed, or reordered event;
- a truncated or corrupted journal;
- an edit to any manifest field: the run name, command line, exit code,
  termination, timestamps, capabilities, the adapter and redaction records,
  diagnostics, or the tenant.

That catches accidental damage and careless edits. **It does not stop someone
who can write to the trace directory.** Nothing in an unsigned trace is
secret, so they can re-chain the events, recompute the chain head, the
journal digest, and the seal, and the result verifies. They can also rewrite
it as a version 1 trace. An unsigned trace that verifies is internally
consistent; it is not evidence that it was never rewritten, and `premier
verify` and the viewer say so.

### What a signature adds

When you verify with `--public-key` and a key you obtained from somewhere you
trust, any change to any event or manifest field after signing is detected,
unless the attacker has the private key. Removing the signature, re-signing
with another key, and downgrading to version 1 all fail against the expected
key.

Limits:

- **The verifier has to bring the key.** The public key stored in the trace
  is not trusted. Without `--public-key`, a signed trace is no stronger than
  an unsigned one.
- **A signing key kept next to the traces it signs protects against nobody
  who can read both.** A process running as your user during a recording can
  read `PREMIER_SIGN_KEY_FILE` and the file it names. Keep the key elsewhere,
  or sign on another host with `premier sign`.
- **A signature says the key holder sealed these bytes.** It does not say who
  that is, when they signed, or that the trace was not altered before it was
  signed. `premier sign` verifies a trace first, but that is the unsigned
  check described above.
- **Re-sealing replaces the signature.** `premier encrypt` and `premier claim`
  write a new seal. The old signature is dropped unless a signing key is
  configured, and a new signature is the statement of whoever ran that
  command. Likewise a signature added by `premier recover` (when
  `PREMIER_SIGN_KEY_FILE` is set) is the recovering party's statement about
  what it found, not the recorder's.

Generating keys and signing are described in
[cli.md](cli.md#signing-keygen-and-sign).

### What no level proves

- **That the events are true.** Verification covers bytes, not meaning. Typed
  events are claims from the recorded process, and adapter events are derived
  from what a CLI printed. The recorder, the recorded process, and anything
  that could write to the journal before finalization are trusted.
- **When anything happened.** Event timestamps are the recording host's
  clock. They are not attested, and nothing proves when a trace was signed.
  A producer's own time (`payload.producer_timestamp`,
  `payload.native_timestamp`) is a claim.
- **That the evidence is complete.** Diagnostics such as an unfinished
  lifecycle or `journal.write_failed` are warnings and do not fail
  verification. Redaction happens before anything is hashed.
- **Anything about an unfinalized trace.** A trace that is still recording or
  was abandoned has no digest and no seal. Its event chain exposes a careless
  edit among complete events, but trailing events can be removed at an event
  boundary without trace, exactly as a crash would leave it. `premier
  recover` keeps the events before the first one that fails its checks,
  finalizes them, marks the trace interrupted, and records
  `seal.recovered: true`. `premier verify` says so for such a trace: it shows
  that the kept events are genuine and in order, not that none were recorded
  after them. This holds for encrypted traces too; see
  [Encrypted traces](#encrypted-traces).
- **That a trace was not deleted or swapped** for a different one that
  verifies.

### Encrypted traces

In an encrypted trace the seal, the journal digest, and the event count are
inside the authenticated, encrypted part of the manifest, and every event
frame is authenticated and bound to its trace and sequence number. Someone
without the encryption key cannot read or edit events, reorder them, change
the format version, or shorten the journal under the finalized manifest, and
still produce a trace that decrypts and verifies as finalized by its
recorder. Someone with the encryption key has the same power over an unsigned
encrypted trace as over an unsigned plaintext one; only a signature
constrains them.

**Limit: rollback to an unfinalized state.** Encryption does not stop someone
without the key from turning a finalized trace back into what looks like an
interrupted recording that ended earlier. The conditions are specific:

1. They kept a copy of `manifest.json` from while the trace was being
   recorded. Every manifest a recorder writes is valid ciphertext under the
   same key, and the manifest's associated data binds only the format
   version, the trace id, and the tenant, not how far the recording had got.
   A manifest of that kind cannot be made without the key; it has to have
   been copied at the time.
2. They put that manifest back and replace the journal with a prefix of it
   cut at a frame boundary, as `events/active.events.pb`. The zstd layer of
   the finalized journal is outside the encryption, so frames can be
   separated without the key; the frames themselves stay authentic.
3. Someone who holds the key then runs `premier recover` on what is, by every
   check available, an abandoned recording.

The result verifies. It is not presented as the original: it is sealed with
`seal.recovered: true`, ends with a `session.interrupted` event stamped with
the time of the recovery, has the interrupted exit status unless the kept
events include `process.exit`, and `premier verify` prints the note described
above. Nothing in the trace format can do better without state kept outside
the trace, because a recording that really was interrupted at that point
leaves exactly these files. What does detect it:

- A signature made at finalization and checked with `verify --public-key`.
  The rolled-back trace carries no signature, or the recovering party's.
- Treating every `seal.recovered` trace as proof of the events it holds and
  not of where the run ended.
- Storage that does not let a reader of the trace directory write to it.

Verifying, signing, and checking a signature on an encrypted trace all need
the encryption key.
