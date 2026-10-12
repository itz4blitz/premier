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
| The recorded process forges the recorder's evidence | The collector rejects recorder-owned kinds and sources | The process can still assert any other event |
| Secrets end up in a trace | Redaction at record and export time | Pattern-based; see [redaction.md](redaction.md#what-this-does-not-catch) |
| Trace files are read from disk or a backup | Owner-only file permissions; optional encryption | The key file sits on the same machine |
| A trace is altered after recording | `premier verify` | Does not stop someone who can rewrite a plaintext manifest |
| Trace content is sent to a model provider | Only through the local assistant, only when you ask it a question, after redaction; can be disabled | Redaction is best effort |

Premier does not defend against a hostile process running as your own user.
Such a process can read your trace files, read the collector token from the
recorded process's environment, and rewrite a trace directory.

## Files on disk

A trace is a directory. On Unix, the recorder creates its directories with
mode `0700` and the manifest and journal files with mode `0600`.

`premier export -o <file>` writes its output with your default umask. It is a
plaintext copy of the trace, redacted but not encrypted.

## The collector

`premier record` starts an HTTP collector for the recorded process
([collector.md](collector.md)).

- It binds `127.0.0.1` on a port chosen by the OS. It is not reachable from
  another machine and cannot be configured to be.
- It is plain HTTP.
- Every recording gets a new bearer token. The token is passed to the
  recorded command in `PREMIER_COLLECTOR_TOKEN`, is compared in constant time,
  and stops working when the recording ends. The collector URL, without the
  token, is stored in the trace's `session.start` event.
- Request bodies are limited to 2 MiB. There is no rate limit.

What the token protects: a local process that does not have it cannot append
events. What it does not protect: anything that can read the recorded
process's environment has the token.

**Recorder-owned evidence.** The recorded process holds the token, so it could
otherwise write its own exit status or terminal output. The collector rejects
(`422`) the kinds `session.start`, `session.interrupted`, and `process.*`, and
the sources `premier`, `command`, `process`, `recorder`, `premier-recovery`,
and `adapter.*`.

Everything else is accepted as sent. An `approval.decision` with
`actor_type: "human"`, a `tool.result` with status `ok`, a model's token
usage: these are claims made by the instrumented process. Premier stores them
and labels their `source`; it does not check them against anything.

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
- `subject` and `tenant_id` are 1-128 ASCII letters, digits, `-`, `_`, `.`,
  or `@`.
- `scopes` may contain `trace:read` and `assistant:use`. Any other value is an
  error. The default is no scopes.

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

### Non-loopback binds and TLS

`premier serve --bind <address>` on anything other than a loopback address
refuses to start unless all of these hold:

1. **TLS is configured**: `--tls-cert` and `--tls-key` (PEM), given together.
   On Unix the key file must not be readable by group or others.
2. **Authentication is configured**: a non-blank password or an auth config.
3. **Every trace in `--trace-dir` is encrypted** and decrypts with the key in
   `PREMIER_TRACE_KEY_FILE`. A plaintext trace, or one encrypted under a
   different key, stops startup with an error naming it.

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

At startup, unless the assistant is disabled, the server looks on `PATH` for
`claude`, `codex`, `grok`, and `gemini`, and runs `<cli> --help` (and
`codex exec --help`) to check that each one supports the flags below. A CLI
that is missing any required flag is listed as unavailable. `opencode` is
listed but never available, because it has no documented non-interactive
read-only mode.

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

The prompt contains:

- a fixed instruction to treat trace content as untrusted data;
- the trace manifest (at most 4,000 characters);
- the selected event, if any (at most 8,000 characters);
- the newest 40 events (at most 24,000 characters in total);
- the conversation so far in the panel (at most 12 messages and 12,000
  characters);
- your question (at most 6,000 characters).

Before it is assembled, the trace content is redacted with the
[`premier export`](redaction.md#premier-export) rules: secret field names and
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
  `PREMIER_TRACE_KEY_FILE`, `PREMIER_COLLECTOR_URL`, and
  `PREMIER_COLLECTOR_TOKEN` are removed from its environment.
- The flags above turn off tools, or restrict the CLI to read-only operation,
  and turn off session persistence where the CLI supports it.
- One request runs at a time; a second gets `429`. The CLI is killed after 45
  seconds, or when the browser disconnects. An answer over 64 KiB is
  discarded.
- The endpoint requires the `assistant:use` scope and passes the Host and
  cross-origin checks like every other API route.

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

Set `PREMIER_TRACE_KEY_FILE` to the path of a key file when recording:

```sh
( umask 077 && openssl rand -hex 32 > ~/.premier-trace.key )
export PREMIER_TRACE_KEY_FILE=~/.premier-trace.key
premier record -- ./agent run
```

- **Format.** A text file containing exactly 64 hexadecimal characters (a
  256-bit key). Leading and trailing whitespace is ignored.
- **Permissions.** On Unix the file must not be accessible by group or
  others. Otherwise every command that needs the key fails with
  `trace key file must not be accessible by group or other users`.

Every command that reads an encrypted trace needs the same variable. Without
it `verify`, `query`, `export`, `diff`, `replay`, `recover`, and `claim` fail
with `encrypted trace requires PREMIER_TRACE_KEY_FILE`; with a different key
they fail with `trace decryption failed: wrong key`. `premier list` skips
traces it cannot read, and the viewer lists them as invalid.

### What is encrypted

A per-trace key is derived from the key file and the trace id with
HKDF-SHA256. Each event is encrypted separately with XChaCha20-Poly1305 and a
random nonce, and is bound to its trace id and sequence number. The sensitive
part of the manifest is encrypted the same way and bound to the trace id and
tenant.

Encrypted: every event; and from the manifest the run name, command line, end
time, exit status and termination, journal digest and event count,
diagnostics, capabilities, and the redaction and adapter records.

### What stays readable on disk

```json
{
  "format_version": 1,
  "trace_id": "01a13085-ebb0-70f3-89f9-1c003492026c",
  "tenant_id": "local",
  "name": null,
  "command": [],
  "started_at": "2026-10-12T14:30:45.429953Z",
  "ended_at": null,
  "exit_code": null,
  "journal": null,
  "capabilities": [],
  "encryption": {
    "algorithm": "XChaCha20-Poly1305",
    "key_id": "sha256:4773d12e2371bb935b9a0f5439b4a1c3",
    "private_manifest": "APqSWhM/PHeDIY8s..."
  }
}
```

- The trace id, tenant id, start time, and format version.
- `key_id`: the first 16 bytes of the SHA-256 of the key, used to tell a
  wrong key from tampering.
- File names, sizes, and modification times, and with them roughly how much
  was recorded and when.
- The size and sequence number of each event frame.
- `recorder.lease`, holding the recorder's process id, while recording.

Other things to know:

- Encryption does not redact. Anyone with the key file reads everything.
- The key file is on the same machine as the traces. It protects copies of
  the trace directory (backups, synced folders, a shared server's disk), not
  a machine whose user account is compromised.
- The recorded command inherits `PREMIER_TRACE_KEY_FILE` in its environment
  and, running as you, can read the file it names.
- What you see in the terminal, and anything `premier export` writes, is
  plaintext.
- There is no command that turns an encrypted trace back into a plaintext
  trace. `premier export` produces a plaintext JSON copy.

### `premier encrypt`

```sh
premier encrypt run.atrace --new-key-file ~/.premier-trace.key
```

Encrypts a finalized plaintext trace, or re-encrypts an encrypted trace under
a new key (the current key is read from `PREMIER_TRACE_KEY_FILE`).

- The trace must be finalized and must pass verification. A trace that fails
  verification is refused, because re-sealing would write a fresh digest over
  whatever happened to decode. There is no `--allow-unverified`.
- It refuses a trace that has files under `blobs/` or `indexes/`, since those
  would stay unencrypted.
- The encrypted copy is written beside the trace, read back, and compared
  event by event with the original before the two directories are swapped. If
  the swap fails the original is put back.
- The original directory is then deleted with an ordinary file removal. It is
  not securely wiped; on most filesystems the old plaintext blocks remain
  until overwritten.

## What verification proves

`premier verify` checks a finalized trace against its own manifest: the
SHA-256 of the journal file, that every frame decodes, the event count, that
every event belongs to this trace, that sequence numbers run from 1 without
gaps, and that event ids are unique. The viewer shows the same result as
`verified` or `invalid`. `query`, `export`, `diff`, `replay`, and `encrypt`
refuse a finalized trace that fails.

It proves:

- The journal has not been corrupted, truncated, or edited since it was
  finalized, **provided the manifest is the one the recorder wrote**.

It does not prove:

- **That nobody rewrote the trace.** In a plaintext trace the digest is an
  unkeyed hash stored in `manifest.json` next to the journal. Someone who can
  write to the directory can change events, recompute the digest and count,
  and produce a trace that verifies.
- **Who recorded it, or when.** Nothing in the current format identifies the
  recorder.
- **That the events are true.** Verification covers bytes, not meaning. Typed
  events are claims from the recorded process, adapter events are derived
  from what a CLI printed, and producer timestamps are stored unvalidated.
- **That the evidence is complete.** Diagnostics such as an unfinished
  lifecycle or `journal.write_failed` are warnings and do not fail
  verification. Redaction happens before the digest is taken.
- **Anything about an unfinalized trace.** A trace that is still recording or
  was abandoned has no digest. `premier recover` finalizes whatever complete
  events are on disk and marks the trace interrupted.

In an encrypted trace the digest and event count are inside the authenticated,
encrypted part of the manifest, and every event frame is authenticated and
bound to its trace and sequence number. Someone without the key cannot edit
events or drop trailing ones and still produce a trace that decrypts and
verifies. Someone with the key can.

For the on-disk format and signing details, see
[trace-format.md](trace-format.md).
