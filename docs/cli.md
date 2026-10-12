# `premier` command reference

This page describes the `premier` binary as built from this repository
(`crates/premier-cli`). The `--help` blocks are pasted from the binary.

```text
$ premier --help
Local-first agent trace recorder and viewer

Usage: premier [OPTIONS] <COMMAND>

Commands:
  record   Record a command and its terminal output into a portable .atrace directory
  demo     Generate a rich local multi-agent trace for product evaluation and onboarding
  emit     Emit a typed agent event to the active local collector (`PREMIER_COLLECTOR_*`)
  verify   Verify a finalized trace's digest, event chain, manifest seal, and signature. Without a signature a trace is only internally consistent (docs/trace-format.md)
  keygen   Generate an Ed25519 signing key: writes the private key (mode 0600) and `<output>.pub`, and prints the public key
  sign     Sign (or re-sign) the manifest seal of an already finalized trace
  recover  Safely finalize an abandoned active trace, discarding only a torn trailing frame
  claim    Atomically claim a legacy/local trace for a tenant
  encrypt  Atomically encrypt a finalized trace, or rotate it to a new master key
  query    Filter local trace evidence without starting the viewer
  export   Export portable JSON evidence with common secret fields recursively redacted. The `redaction` block reports the active rules and what was removed
  diff     Compare two traces by semantic event structure, ignoring generated identity noise
  replay   Replay recorded evidence timing only; this never re-executes the traced command. A recorded gap longer than 10 seconds is replayed as 10 seconds
  list     List traces in a directory
  open     Open the local viewer, optionally focused on one trace
  serve    Serve the viewer locally or to an authenticated team
  help     Print this message or the help of the given subcommand(s)

Options:
      --key-file <PATH>  Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
  -h, --help             Print help
  -V, --version          Print version
```

## Conventions

- A trace is a directory, by convention named `*.atrace`. The default trace
  directory is `.premier/traces` relative to the current directory. The
  on-disk format is specified in [trace-format.md](trace-format.md).
- Exit codes, for every command except `record`:

  | Code | Meaning |
  | --- | --- |
  | `0` | Success. |
  | `1` | The command failed. The reason is printed to stderr as `Error: ...`. |
  | `2` | Invalid command line (unknown flag, missing argument, out-of-range value). |
  | `141` | Unix only, as reported by a shell: `verify`, `query`, `export`, `diff`, `replay`, or `list` was writing to a pipe whose reader went away. See [Text output](#text-output). |

  `record` returns the recorded command's own status; see
  [Exit status](#exit-status). It uses `1` and `2` as above only when it fails
  before the command starts (for example an invalid `--redact-regex`).
- Environment variables read by the CLI:

  | Variable | Used by | Meaning |
  | --- | --- | --- |
  | `PREMIER_TRACE_KEY_FILE` | every command that writes or reads a trace | Path to the encryption key file. Environment form of the global `--key-file`. See [The global `--key-file` option](#the-global---key-file-option). |
  | `PREMIER_SIGN_KEY_FILE` | `record`, `demo`, `sign`, `encrypt`, `recover`, `claim` | Path to an Ed25519 private key from `premier keygen`. Environment form of `--sign-key` on `record`, `sign`, and `encrypt`; `demo`, `recover`, and `claim` have no flag and read only the variable. See [Signing](#signing-keygen-and-sign). |
  | `PREMIER_STOP_GRACE_MS` | `record` | Milliseconds a child may outlive a forwarded SIGTERM, SIGHUP, or SIGQUIT before it is killed. Default `10000`. |
  | `PREMIER_REDACTION_IDLE_FLUSH_MS` | `record` | Milliseconds a stream must be quiet before output held back for a redaction rule is stored. Default `1000`. See [redaction.md](redaction.md#idle-flush). |
  | `PREMIER_COLLECTOR_URL`, `PREMIER_COLLECTOR_TOKEN` | `emit` | Collector endpoint and bearer token. `record` sets them for the recorded process. |
  | `PREMIER_EMIT_TIMEOUT` | `emit` | Seconds to wait for the collector. Default `10`. |
  | `PREMIER_DISABLE_ASSISTANT` | `open`, `serve`, `record --open` | Any value other than empty, `0`, `false`, `no`, or `off` disables the local assistant. |
  | `PREMIER_PASSWORD`, `PREMIER_AUTH_CONFIG`, `PREMIER_TLS_CERT`, `PREMIER_TLS_KEY` | `serve` | Environment forms of `--password`, `--auth-config`, `--tls-cert`, `--tls-key`. |

  `record` also sets `PREMIER_TRACE_ID` for the recorded process.

### The global `--key-file` option

`--key-file <PATH>` is accepted by every subcommand, before or after the
subcommand name, and is listed in every `--help` block below. It names the
trace encryption key file:

- `premier record` and `premier demo` write the new trace encrypted.
- Every command that reads a trace uses it to open an encrypted one.
- `PREMIER_TRACE_KEY_FILE` is the environment form. When both are given the
  flag wins.
- The file holds one 256-bit key as exactly 64 hexadecimal characters;
  surrounding whitespace is ignored. On Unix it must not be accessible by group
  or others.

```sh
( umask 077 && openssl rand -hex 32 > ~/.premier-trace.key )
premier --key-file ~/.premier-trace.key record -- ./agent run
premier verify run.atrace --key-file ~/.premier-trace.key
```

With the flag, `premier` does not put the path into the recorded command's
environment. With the variable, the recorded command inherits it like any
other variable. Details and limits are in
[security.md](security.md#encryption-at-rest).

### Text output

The human-readable output of `verify`, `query`, `diff`, and `list` shows
recorded text (trace ids, run names, command lines, kinds, actors, statuses,
diagnostic messages) with control characters and invisible or
direction-changing Unicode format characters written as escapes such as
`\u{1b}` and `\n`. Recorded text therefore cannot drive the terminal or forge
an extra output line. JSON output (`--json`, `export`, `replay`) is not
escaped this way and stays exact.

```text
$ premier record -o esc.atrace --name "$(printf 'evil\033[31m name\nline2')" -- true
$ premier list --trace-dir .
01a130a7-9ac1-74b0-954c-ced493871dab  2026-10-12 15:07:32.936658 UTC  evil\u{1b}[31m name\nline2
```

On Unix, `verify`, `query`, `export`, `diff`, `replay`, and `list` restore the
default SIGPIPE behaviour. When the reader of their output closes the pipe
(`premier query run.atrace | head -1`) they end silently, killed by SIGPIPE,
which a shell reports as status `141`. `record`, `open`, and `serve` keep
ignoring SIGPIPE.

## `record`

```text
$ premier record --help
Record a command and its terminal output into a portable .atrace directory

Usage: premier record [OPTIONS] <COMMAND>...

Arguments:
  <COMMAND>...  

Options:
      --key-file <PATH>
          Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
  -o, --output <OUTPUT>
          
      --name <NAME>
          Human-readable run name shown by list and the trace viewer
      --tenant <TENANT>
          Immutable tenant owner recorded in the trace manifest [default: local]
      --open
          Open the viewer focused on this recording when it finishes
      --pty
          Run the command inside a pseudo-terminal (Unix only), preserving stdout/stderr ordering as one interactive terminal byte stream
      --adapter <ADAPTER>
          Normalize a provider's native JSONL stream into typed evidence. Auto activates only when a recognized CLI already uses structured output [default: auto]
      --viewer-dir <VIEWER_DIR>
          Optional disk viewer (for local UI development). Default: embedded viewer
      --bind <BIND>
          [default: 127.0.0.1:4317]
      --redact-field <REDACT_FIELDS>
          Additional structured payload field name to redact recursively
      --redact-literal <REDACT_LITERALS>
          Exact text to redact from persisted terminal output, event payloads, and the recorded command line (terminal display stays raw)
      --redact-regex <REDACT_REGEXES>
          Regex to redact from persisted terminal output, event payloads, and the recorded command line (terminal display stays raw). Regex rules are line-scoped: in terminal output a match never spans a line break, so write one rule per line of a multi-line secret. A line longer than 256 KiB is stored in pieces, and only a match up to 16 KiB is guaranteed across such a cut. A partial line (such as a prompt) is stored after 1 second without output, so a match the output pauses inside can be split; use --redact-literal for exact secrets. Set PREMIER_REDACTION_IDLE_FLUSH_MS to change that idle period (in milliseconds)
      --redact-regex-multiline <REGEX>
          Regex to redact that may match across line breaks, such as a multi-line token or key block. It applies to the same places as --redact-regex, with the same syntax (`.` crosses a line break only with `(?s)`; `\n` and `\s` always can). In terminal output it is matched over a sliding window: the most recent 16 KiB are held back, so a match up to 16 KiB is redacted however the output was split into lines and writes, and a longer match may be stored in part. In structured payloads it is matched over each whole string value. Held output is still stored after the idle period described under --redact-regex
      --no-default-secret-patterns
          Do not apply the built-in secret value patterns (API keys, bearer credentials, URL passwords, private key blocks, JWTs) to structured event payloads and the recorded command line
      --redact-known-secrets
          Also apply the built-in secret value patterns to persisted terminal output, which is otherwise stored raw unless a --redact-literal or --redact-regex rule matches
      --sign-key <PATH>
          Ed25519 private key file (from `premier keygen`) used to sign the trace when it is finalized [env: PREMIER_SIGN_KEY_FILE=]
  -h, --help
          Print help
```

```sh
premier record -- npm test
premier record --name "nightly eval" -o runs/nightly.atrace -- ./agent run
premier record --sign-key ~/.premier-sign.key -- ./agent run
```

Everything after `--` is the command. Options must come before it.

| Option | Notes |
| --- | --- |
| `-o, --output` | Trace directory to create. Default `.premier/traces/trace-<unix-milliseconds>.atrace`. Parent directories are created. Recording fails if the path already exists. |
| `--name` | Run name. The redaction rules apply to it. |
| `--tenant` | 1-128 ASCII letters, digits, `.`, `_`, or `-`. Default `local`. `--open` is rejected for any tenant other than `local`. |
| `--open` | After the trace is finalized, serve the viewer for this one trace on `--bind` and open a browser. Skipped when the recorder received a stop signal. `--viewer-dir` and `--bind` only matter with `--open`. |
| `--pty` | See [PTY capture](#pty-capture). |
| `--adapter` | `auto`, `none`, `codex`, `claude`, `gemini`, `grok`, `opencode`, `kimi`, or `droid`. `auto` recognises the agent by executable name and structured-output flag, also behind `env`, a package runner (`npx`, `bunx`, `pnpx`, `pnpm dlx`, `yarn dlx`), or `sh -c` with one simple command; arguments after the command's own `--` are not read as flags. See [adapters.md](adapters.md#when-an-adapter-runs). |
| `--redact-*`, `--no-default-secret-patterns` | Repeatable where they take a value. An invalid `--redact-regex` or `--redact-regex-multiline` pattern stops `record` before anything runs. See [redaction.md](redaction.md). |
| `--sign-key` | Signs the manifest seal when the trace is finalized. The key file is loaded before the command starts; a missing, malformed, or group/other-accessible key file stops `record` with exit `1` and nothing runs. See [Signing](#signing-keygen-and-sign). |
| `--key-file` | Writes the trace encrypted. See [The global `--key-file` option](#the-global---key-file-option). |

What `record` does:

1. Creates the trace directory and starts a loopback HTTP collector on a random
   port (see [collector.md](collector.md)).
2. Starts the command with `PREMIER_TRACE_ID`, `PREMIER_COLLECTOR_URL`, and
   `PREMIER_COLLECTOR_TOKEN` added to its environment. Standard input is
   inherited. The token's value is replaced with `[REDACTED]` wherever it
   would be stored, for example when the command prints its environment; see
   [redaction.md](redaction.md#the-collector-token).
3. Copies the command's stdout and stderr to its own stdout and stderr
   unchanged, and stores them as `process.stdout` / `process.stderr` events. If
   the recorder's own stdout or stderr is closed (for example
   `premier record -- cmd | head`), mirroring stops and capture continues.
4. When the command exits, appends `process.exit`, stops the collector,
   finalizes the trace (journal digest, event chain head, manifest seal, and
   the signature when a signing key is configured), and prints the trace id and
   path to stderr.

A descendant that keeps the output pipe open does not block finalization.
After the command exits, the recorder keeps reading until the stream has been
quiet for 250 ms, or for at most 5 seconds, then finalizes and sets
`output_open_at_exit: true` on `process.exit`.

A collector client that keeps a request open does not block finalization
either. Once the command has exited, requests in flight get 2 seconds to
finish; whatever is still open after that is dropped. See
[collector.md](collector.md#lifetime).

### Exit status

`record` exits with the status of the recorded command:

| Recorded command | `record` exit status | `process.exit` payload |
| --- | --- | --- |
| Exits with code `N` | `N` | `termination: "exit"`, `exit_code: N` |
| Killed by signal `S` | `128 + S` | `termination: "signal"`, `signal`, `signal_name`, `exit_code: 128 + S` |
| Not found | `127` | none; see [Spawn failure](#spawn-failure) |
| Found but not executable | `126` | none; see [Spawn failure](#spawn-failure) |

The status is always the child's own wait status. A stop signal received by
the recorder is recorded separately and does not replace it: a child that
handles SIGTERM and exits `0` is recorded, and returned, as exit `0`. When the
recorder received a signal, `process.exit` also carries:

| Field | Meaning |
| --- | --- |
| `forwarded_by_recorder: true` | The recorder received a stop signal while the command ran. |
| `recorder_signal`, `recorder_signal_name` | The first such signal, by number and name. |
| `killed_by_recorder: true` | The recorder sent SIGKILL (grace period expired, or three rapid interrupts). |

`core_dumped: true` is added when the child's wait status reports a core dump.
The manifest stores the same outcome in `exit_code` and `termination`.

Recorder failures do not change the exit status. If the trace cannot be
finalized, the recorder prints the error and the `premier recover --force`
command that salvages it, then still exits with the command's status.

### Signals

Unix only. The recorder handles SIGINT, SIGTERM, SIGHUP, and SIGQUIT, relays
them to the command, waits for it to exit, and finalizes the trace.

| Signal | Behaviour |
| --- | --- |
| SIGTERM, SIGHUP, SIGQUIT | Forwarded as the same signal. If the command is still running after the grace period it is sent SIGKILL. |
| SIGINT | Forwarded with no deadline, because interactive agents handle an interrupt and keep running. The third SIGINT, each within 2 seconds of the previous one, sends SIGKILL instead. |

- The grace period is 10 seconds. `PREMIER_STOP_GRACE_MS` overrides it (an
  integer number of milliseconds; an unparsable value is ignored).
- Without `--pty` the command shares the recorder's foreground process group,
  so the terminal has already delivered a Ctrl-C or Ctrl-\ to it. The recorder
  does not send that signal a second time. Ctrl-\ still starts the grace
  period.
- With `--pty` signals are sent to the command's process group.
- On Linux the kernel marks terminal-generated signals, so the recorder tells a
  Ctrl-C from `kill -INT <recorder pid>` exactly and relays the latter.
- **macOS caveat.** macOS gives no such marker. The recorder treats any SIGINT
  or SIGQUIT as terminal-generated whenever it is in the foreground process
  group of its controlling terminal. An external `kill -INT` aimed at a
  foreground recorder is therefore not relayed to the command. Send SIGTERM
  instead, or send SIGINT three times within the 2-second window to kill the
  command. A recorder that is not in the foreground (a background job, a
  supervisor, CI) relays `kill -INT` normally.

The npm launcher adds its own forwarding layer; see
[packages/premier-cli/README.md](../packages/premier-cli/README.md).

### Spawn failure

When the command cannot be started nothing runs, and the trace is still
finalized as evidence of the failed start:

- The recorder exits `127` if the executable was not found and `126` if it was
  found but could not be executed.
- The trace contains `session.start` followed by `process.spawn_failed`
  (source `premier`, status `error`) with payload `executable`, `error`,
  `exit_code`, and `success: false`. There is no `process.exit` event.
- The manifest records the same exit code.

```text
$ premier record -o missing.atrace -- definitely-not-a-command
premier: failed to start definitely-not-a-command: command not found (No such file or directory (os error 2)); nothing was run (exit status 127)
trace 01a130a6-c989-73f3-9421-0afd223c14d0 → missing.atrace
$ echo $?
127
```

### Journal write failure

A failed journal write (full disk, quota, file size limit) never stops the
recorded command or its output:

- The first failure prints `premier: recording failed: ...` and
  `premier: the command keeps running, but its trace is incomplete` to stderr.
- The journal is rolled back to the last complete event, so later events are
  still appended in order when writes succeed again.
- At the end the recorder prints how many events are missing, and the manifest
  gets a `journal.write_failed` diagnostic with the count.
- The exit status is still the command's.

### PTY capture

`--pty` runs the command inside a pseudo-terminal, for interactive programs
that need a terminal.

- Unix only.
- stdout and stderr are one merged stream, stored as `process.terminal` events
  (`stream: "pty"`). The manifest gains the `terminal.pty` and
  `terminal.merged-output` capabilities, and `session.start` records
  `capture_mode: "pty"` and the terminal size.
- The terminal size is read once at start from the recorder's terminal, falling
  back to `LINES` / `COLUMNS` and then 24x80.
- When stdin is a terminal the recorder puts it in raw mode for the duration
  and restores it afterwards.
- Native adapters do not run under `--pty`. `--adapter auto` records terminal
  output only, and naming an adapter explicitly together with `--pty` is an
  error. When `auto` would have activated an adapter for the command, the
  recorder says so once on stderr before the command starts:
  `premier: structured capture for <provider> is unavailable in PTY mode;
  recording terminal output only (omit --pty for model and tool events)`.

## `demo`

```text
$ premier demo --help
Generate a rich local multi-agent trace for product evaluation and onboarding

Usage: premier demo [OPTIONS]

Options:
      --key-file <PATH>  Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
  -o, --output <OUTPUT>  [default: .premier/traces/multi-agent-demo.atrace]
  -h, --help             Print help
```

Writes a synthetic, finalized trace (source `premier-demo`, exit code `1`)
that exercises delegation, subagents, approvals, a failed tool call, and a
join. Nothing is executed.

`--output` replaces an existing directory only when it is recognisably a
Premier trace: its `manifest.json` parses as a trace manifest and it contains
nothing but trace files. Anything else, a symlink, the current directory, or
an ancestor of the current directory is refused.

## `emit`

```text
$ premier emit --help
Emit a typed agent event to the active local collector (`PREMIER_COLLECTOR_*`)

Usage: premier emit [OPTIONS]

Options:
      --json <JSON>                Full JSON event body. Use `-` to read from stdin
      --key-file <PATH>            Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --kind <KIND>                Event kind (e.g. agent.spawn, model.response, tool.execution)
      --actor <ACTOR>              Actor identity for this event
      --actor-type <ACTOR_TYPE>    [default: agent]
      --span <SPAN>                
      --parent-span <PARENT_SPAN>  
      --status <STATUS>            
      --payload <PAYLOAD>          Payload as a JSON object string
      --source <SOURCE>            Source label written on the event (default: premier-emit) [default: premier-emit]
  -h, --help                       Print help
```

```sh
premier emit --kind tool.execution --actor coder --status ok --payload '{"tool":"rg"}'
echo '{"kind":"agent.message","actor_id":"a","status":"ok","payload":{}}' | premier emit --json -
```

- Requires `PREMIER_COLLECTOR_URL` and `PREMIER_COLLECTOR_TOKEN`, which
  `premier record` sets for the recorded process. Outside a recording `emit`
  exits `1`.
- Provide `--json` or `--kind`. With `--json` the body is sent as given and the
  other flags are ignored. The flags cannot set `parent_event_id`,
  `correlation_id`, `links`, `duration_ms`, or `timestamp`; use `--json` for
  those.
- On success prints the new event id and exits `0`.
- Exits `1` when the collector is unreachable, does not answer in time, or
  rejects the event. The message includes the HTTP status and response body.
  The collector validates every field; see
  [collector.md](collector.md#field-rules).
- `PREMIER_EMIT_TIMEOUT` is the number of seconds to wait (decimals allowed).
  The default is `10`; a value that is not a positive number is ignored.
- **Proxy bypass.** When the collector URL is loopback (`localhost`, a
  `.localhost` name, `127.0.0.0/8`, or `::1`), `emit` ignores `HTTP_PROXY`,
  `HTTPS_PROXY`, and `ALL_PROXY`, so the token and payload never pass through
  a proxy. For any other collector URL the environment's proxy settings are
  used.

The body fields and the collector's responses are documented in
[collector.md](collector.md).

## `verify`

```text
$ premier verify --help
Verify a finalized trace's digest, event chain, manifest seal, and signature. Without a signature a trace is only internally consistent (docs/trace-format.md)

Usage: premier verify [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>           Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --public-key <PATH-OR-HEX>  Require a valid signature by this Ed25519 public key (64 hex characters, or a file containing them)
  -h, --help                      Print help
```

Checks, in order:

1. The manifest reads and has format version 1 or 2 (and, for an encrypted
   trace, decrypts with the configured key).
2. The manifest names the canonical journal path, and the SHA-256 of the
   compressed journal file equals the digest in the manifest.
3. Every frame decodes.
4. The number of events equals the count in the manifest.
5. Every event carries the manifest's trace id.
6. Sequences are contiguous from 1, and event ids are non-empty and unique.
7. Version 2 only: every event names the hash of its predecessor, and the last
   hash equals the chain head in the manifest seal.
8. Version 2 only: the seal digest matches the manifest's fields.
9. When the seal carries a signature: it is a valid Ed25519 signature by the
   public key stored beside it.
10. With `--public-key`: the trace is signed, and by that key.

The chain, seal, and signature are specified in
[trace-format.md](trace-format.md).

A successful verification exits `0` and its first stdout line says how far the
result goes. Only a signature by a key you supplied is called `verified`:

| First line begins | When | Followed by |
| --- | --- | --- |
| `verified: chain and seal valid, signed by the supplied key <fingerprint>:` | All checks pass and the signer is the `--public-key` key. | nothing |
| `consistent: chain and seal valid, signed by an unknown key <fingerprint>:` | Checks 1 to 9 pass and no `--public-key` was given. The signature is valid for the key stored in the trace itself. | `note: the signature is valid for the key stored in the trace itself, which says nothing about who signed it; pass --public-key with a key you trust` |
| `consistent: chain and seal valid, unsigned:` | Checks 1 to 8 pass and the trace has no signature. | `note: an unsigned trace is only internally consistent. ...` |
| `consistent (v1: digest only):` | A version 1 trace: checks 1 to 6 only. | `note: version 1 traces have no event chain, seal or signature; ...` |

The rest of that line is `<trace id> (<n> events, <m> semantic diagnostics)`.
After the note comes one `warning <code> at sequence <n>: <message>` line per
diagnostic.

```text
$ premier verify plain.atrace
consistent: chain and seal valid, unsigned: 01a130a6-5150-7631-b059-e864addfee77 (3 events, 0 semantic diagnostics)
note: an unsigned trace is only internally consistent. That catches accidental or careless changes; anyone who can write to the trace can rebuild the chain and seal. Sign traces (premier keygen, record --sign-key, premier sign) for tamper evidence
$ premier verify signed.atrace --public-key signer.key.pub
verified: chain and seal valid, signed by the supplied key sha256:6f993d9bfe2cbf04ba8e18f506675153: 01a130a6-51e5-7a93-bfc3-9903396ca127 (3 events, 0 semantic diagnostics)
```

`--public-key` takes 64 hexadecimal characters or the path of a file that
contains them, such as the `.pub` file `premier keygen` writes.

Failures exit `1`:

| Outcome | Output on stderr |
| --- | --- |
| Still being recorded | `Error: trace is not finalized (still recording)` |
| Abandoned | `Error: trace is not finalized (abandoned: the recorder is no longer running — run ...)`, naming the `premier recover` command to run |
| A check failed | `Error: invalid: <trace> failed verification`, then `Caused by:` and the reason, for example `journal digest mismatch`, `event count mismatch`, `event chain head does not match the manifest seal`, or `manifest seal mismatch: a manifest field was changed after finalization` |
| `--public-key` given, trace unsigned | reason `trace is not signed` |
| `--public-key` given, signed by another key | reason `trace is signed by a different key (<fingerprint>), not the supplied key (<fingerprint>)` |
| `--public-key` given, version 1 trace | reason `version 1 traces cannot carry a signature (v1: digest only)` |
| Encrypted trace, no key | reason `encrypted trace requires --key-file or PREMIER_TRACE_KEY_FILE` |
| Encrypted trace, another key | reason `trace decryption failed: wrong key` |

```text
$ premier verify tampered.atrace
Error: invalid: tampered.atrace failed verification

Caused by:
    manifest seal mismatch: a manifest field was changed after finalization
```

Diagnostics are warnings about the recorded events (see
[events.md](events.md#lifecycle-validation)). They do not fail verification.

What each outcome does and does not prove is covered in
[security.md](security.md#what-verification-proves).

### `verify --live`

`premier verify <TRACE>` on a trace that is not finalized fails and points
here. `premier verify --live <TRACE>` checks the active journal of a trace
that is still recording or was abandoned: it validates each frame and the
format v2 hash chain up to the last complete frame and prints the event count.
It modifies nothing. A frame that cannot be genuine (zero length, an empty
event, another trace's id, a sequence that does not follow its predecessor, or
a chain mismatch) makes it print `invalid:` with the reason and exit non-zero.
A torn trailing frame is not an error. On a finalized trace `--live` changes
nothing: the trace is verified as usual.

## Signing: `keygen` and `sign`

A signature is optional. It is an Ed25519 signature over the manifest seal,
which in turn covers every manifest field and, through the chain head, every
event. See [trace-format.md](trace-format.md#signature).

```text
$ premier keygen --help
Generate an Ed25519 signing key: writes the private key (mode 0600) and `<output>.pub`, and prints the public key

Usage: premier keygen [OPTIONS] <OUTPUT>

Arguments:
  <OUTPUT>  Private key file to create. Must not already exist

Options:
      --key-file <PATH>  Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
  -h, --help             Print help
```

```text
$ premier keygen signer.key
wrote private signing key to signer.key (owner-only); keep it secret
wrote public key to signer.key.pub
public key: e5f5b4620cbcf6becd1534a20bf456582509028c5763fa12360247d1071ea926
fingerprint: sha256:6f993d9bfe2cbf04ba8e18f506675153
```

- The private key file is created with mode `0600` and holds the 32-byte
  Ed25519 seed as 64 hexadecimal characters. `keygen` fails if the file
  already exists.
- `<output>.pub` holds the public key as 64 hexadecimal characters. It is safe
  to share, and is what `premier verify --public-key` takes.
- The fingerprint is `sha256:` followed by the first 16 bytes of the SHA-256
  of the raw public key, in hex. `verify`, `sign`, the API, and the viewer
  identify a signer by it.
- A private key file that is accessible by group or others is refused by every
  command that loads it: `signing key file must not be accessible by group or
  other users`.

```text
$ premier sign --help
Sign (or re-sign) the manifest seal of an already finalized trace

Usage: premier sign [OPTIONS] --sign-key <PATH> <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>  Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --sign-key <PATH>  [env: PREMIER_SIGN_KEY_FILE=]
  -h, --help             Print help
```

```text
$ premier sign plain.atrace --sign-key signer.key
signed 01a130a6-5150-7631-b059-e864addfee77 with key sha256:6f993d9bfe2cbf04ba8e18f506675153
```

- `--sign-key` (or `PREMIER_SIGN_KEY_FILE`) is required.
- The trace must be finalized and must pass verification first, so a signature
  is never added to altered evidence.
- An existing signature is replaced. Nothing else in the trace changes.
- A version 1 trace is refused: `version 1 traces have no seal to sign (v1:
  digest only)`.
- An encrypted trace needs its encryption key as well.

Where a signature comes from:

| Command | Signs when |
| --- | --- |
| `record` | `--sign-key` or `PREMIER_SIGN_KEY_FILE` is set. |
| `demo` | `PREMIER_SIGN_KEY_FILE` is set. |
| `sign` | Always. |
| `recover` | `PREMIER_SIGN_KEY_FILE` is set. The signature is then the recovering party's, not the original recorder's. |
| `encrypt`, `claim` | They change sealed fields, so the seal is recomputed and an existing signature no longer applies. `encrypt --sign-key` or `PREMIER_SIGN_KEY_FILE` (for `claim`, the variable only) signs the new seal; otherwise the old signature is dropped and the command prints a warning. |

## Abandoned traces and `recover`

```text
$ premier recover --help
Safely finalize an abandoned active trace, discarding only a torn trailing frame

Usage: premier recover [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>
          Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --stale-after-seconds <STALE_AFTER_SECONDS>
          Minimum journal idle time required before recovery [default: 300]
      --force
          Recover even when the journal was modified recently
  -h, --help
          Print help
```

While it runs, a recorder keeps a lease file, `recorder.lease`, in the trace
directory and rewrites it every 2 seconds. The lease names the recorder by
process id and process start time:

```text
51030 start=1791817650101132
```

`start=` is an opaque number that stays the same for the life of a process and
differs for a later process that is given the same id. It is field 22 of
`/proc/<pid>/stat` on Linux (clock ticks since boot) and the process start
time in microseconds since the epoch on macOS. On other platforms, and in a
lease written by an older recorder, the lease holds the process id alone.

A trace with no finalized journal is classified from that lease:

| Lease | State | `list` shows |
| --- | --- | --- |
| Names a live process whose start time matches | recording, however long ago the lease was last rewritten | `[recording]` |
| Names a process that no longer exists, or a live process with a different start time (the id was reused) | abandoned | `[abandoned: ...]` with the command `premier recover <trace>` |
| Has no start time, names a live process, and was written less than 300 s ago | recording | `[recording]` |
| Missing or unreadable; or has no start time, names a live process, and is 300 s or more old (the id was probably reused) | abandoned | `[abandoned: ...]` with `premier recover <trace>`, or `premier recover --force <trace>` while the journal or lease was modified less than 300 s ago |

**Suspended recorders.** A recorder that is stopped (SIGSTOP, Ctrl-Z, a
sleeping laptop) stops rewriting its lease but still exists. Because the lease
carries its start time, it is still classified as recording, and `recover`
refuses it without `--force` no matter how stale the lease has become.

A recorder that was killed outright (SIGKILL, power loss, a crash) leaves an
abandoned trace. `premier verify` refuses it and prints the recover command.
The viewer shows it as abandoned.

`premier recover <trace>` decides as follows:

1. A finalized trace is refused: `trace is already finalized`.
2. With `--force`, recovery proceeds.
3. If the lease names a live recorder (same rule as above), recovery is
   refused: `trace is still being recorded by process <pid>; stop that
   recorder and let it finalize the trace, or pass --force to finalize it
   anyway`.
4. If the lease names a dead process, recovery proceeds immediately.
5. Otherwise the staleness rule applies: the newer of the journal's and the
   lease's modification time must be at least `--stale-after-seconds` old
   (default 300), or recovery is refused with
   `trace appears active (journal idle for <n>s; require 300s or pass --force)`.

Recovery keeps every complete event, discards a torn trailing frame, and
appends one `session.interrupted` event (source `premier-recovery`, status
`error`) whose payload records `reason: "recorder_interrupted"`,
`recovered_event_count`, and `discarded_trailing_bytes`. The manifest gets
`termination.kind: "interrupted"` and `exit_code: 130`. The real exit status
of the command is unknown and is not invented.

For a version 2 trace, recovery first checks the event chain over the complete
frames and refuses a journal whose chain is broken (`cannot recover: the
active journal failed chain verification`). The recovered trace is sealed with
`seal.recovered: true`, and signed when `PREMIER_SIGN_KEY_FILE` is set.

```text
$ premier list --trace-dir .
01a130a7-90c7-7e40-b2e9-9a029dfb6ed5  2026-10-12 15:07:30.392745 UTC  sh -c echo started; sleep 6  [abandoned: the recorder is no longer running — run `premier recover ./live.atrace`]
$ premier recover live.atrace
recovered 01a130a7-90c7-7e40-b2e9-9a029dfb6ed5 (3 events, exit 130)
```

`--force` on a trace whose recorder is still running finalizes it underneath
that recorder. Stop the recorder first. Recovery removes the lease, and a
recorder that is still running does not write it again.

### Damaged journals

`recover` salvages the longest valid prefix of the active journal. It keeps
every frame before the first one that cannot be genuine, copies those frames
unchanged, appends `session.interrupted`, and finalizes. It never fabricates
events. What was dropped is reported on stdout (bytes, and frames when that can
be known, with the sequence after which the cut was made and the reason) and
recorded in three places: `seal.discarded_bytes` and `seal.discarded_frames`
in the manifest, a `journal.recovery_discarded` diagnostic, and the
`session.interrupted` payload. The discarded bytes themselves are not kept.

When an event fails to chain to its predecessor, nothing says which of the two
was altered, so recovery drops both.

`recover --sign-key <PATH>` (env `PREMIER_SIGN_KEY_FILE`) signs the recovered
trace. That signature is the recovering party's statement about what it found,
not the recorder's.

A finalized journal that has been cut short is a different case: every reader
fails with `journal is truncated`, and `verify` reports a digest mismatch.
`query`, `export`, `diff`, and `replay` no longer read a truncated journal as
an empty or shorter trace.

## `claim`

```text
$ premier claim --help
Atomically claim a legacy/local trace for a tenant

Usage: premier claim [OPTIONS] --tenant <TENANT> <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>  Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --tenant <TENANT>  
  -h, --help             Print help
```

Changes the manifest's `tenant_id` from `local` to `--tenant`. Only a trace
owned by `local` can be claimed, so a trace can be claimed once. Tenant ids
are 1-128 ASCII letters, digits, `.`, `_`, or `-`. Tenants matter to
`premier serve --auth-config`; see [security.md](security.md#authentication-and-scopes).

The owner is a sealed field, so the manifest seal is recomputed. A signature
on the trace covered the old manifest and is dropped, unless
`PREMIER_SIGN_KEY_FILE` names a key to sign the new seal with:

```text
$ premier claim claim1.atrace --tenant acme
claimed 01a130a6-51e5-7a93-bfc3-9903396ca127 for tenant acme
warning: the previous signature covered the old manifest and was dropped; re-sign with `premier sign`
```

With the variable set the second line is `re-sealed and signed with the
configured signing key`. Both lines go to stdout.

## `encrypt`

```text
$ premier encrypt --help
Atomically encrypt a finalized trace, or rotate it to a new master key

Usage: premier encrypt [OPTIONS] --new-key-file <PATH> <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>      Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --new-key-file <PATH>  
      --sign-key <PATH>      Re-sign the re-sealed trace. Without a key an existing signature is dropped [env: PREMIER_SIGN_KEY_FILE=]
  -h, --help                 Print help
```

`--new-key-file` is the key the trace is encrypted under afterwards.
`--key-file` (or `PREMIER_TRACE_KEY_FILE`) is the current key, needed only
when the trace is already encrypted and is being rotated.

Events are re-encrypted unchanged, so the event chain and its head are
preserved. The journal digest and the encryption envelope are sealed fields,
so the seal is recomputed and an existing signature no longer applies:

```text
$ premier encrypt enc1.atrace --new-key-file trace.key
encrypted 01a130a6-51e5-7a93-bfc3-9903396ca127 (enc1.atrace)
warning: the previous signature covered the old manifest and was dropped; re-sign with `premier sign`
$ premier encrypt enc2.atrace --new-key-file trace.key --sign-key signer.key
encrypted 01a130a6-51e5-7a93-bfc3-9903396ca127 (enc2.atrace)
re-sealed and signed with the configured signing key
```

(`enc1.atrace` and `enc2.atrace` are two copies of the same signed trace.)
Both result lines go to stdout.

The rest is in [security.md](security.md#premier-encrypt).

## `query`

```text
$ premier query --help
Filter local trace evidence without starting the viewer

Usage: premier query [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>   Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --kind <KIND>       Exact event kind, matched case-insensitively
      --actor <ACTOR>     Exact actor id, matched case-insensitively
      --status <STATUS>   Exact event status, matched case-insensitively
      --search <SEARCH>   Case-insensitive search across event metadata and payload JSON
      --limit <LIMIT>     Maximum events returned (1-1000) [default: 100]
      --json              Emit one structured JSON result instead of the compact text view
      --allow-unverified  Read a finalized trace even though it fails `premier verify`
  -h, --help              Print help
```

```sh
premier query run.atrace --status error
premier query run.atrace --kind tool.result --search "exit_code" --json
```

- Filters are combined with AND. `--search` matches against kind, source,
  actor id, actor type, status, and the payload JSON text.
- The text view prints `sequence  timestamp  kind  actor  status` per event on
  stdout and `<n> matched; <m> returned` on stderr. An event with an empty
  `actor_id` shows `-` in the actor column: it is unattributed, not the root
  process. Text is escaped as described under [Text output](#text-output).
- `--json` prints `{"matched", "returned", "truncated", "events"}`. Events are
  printed as stored; `query` applies no redaction.

```text
$ premier query col.atrace --kind agent.message
     3  2026-10-12T15:06:37.685688+00:00  agent.message            a                  ok
     7  2026-10-12T15:06:37.762336+00:00  agent.message            a                  ok
    12  2026-10-12T15:06:37.805029+00:00  agent.message            -                  
    25  2026-10-12T15:06:37.899920+00:00  agent.message            -                  
4 matched; 4 returned
```

## `export`

```text
$ premier export --help
Export portable JSON evidence with common secret fields recursively redacted. The `redaction` block reports the active rules and what was removed

Usage: premier export [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>             Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
  -o, --output <OUTPUT>             Destination JSON file. Omit to write JSON to stdout
      --no-default-secret-patterns  Do not apply the built-in secret value patterns (API keys, bearer credentials, URL passwords, private key blocks, JWTs) to structured event payloads and the recorded command line
      --redact-known-secrets        Also apply the built-in secret value patterns to captured terminal output, which is otherwise exported as recorded
      --allow-unverified            Export a finalized trace even though it fails `premier verify`
  -h, --help                        Print help
```

Writes one JSON document with `format: "premier.portable-evidence.v1"`, a
`redaction` report, a `source` block, the manifest, and every event with its
payload decoded.

- With `--output` the file is written through a temporary file and a rename,
  and on Unix is created with mode `0600`, whatever the umask.
- The `source` block copies the source trace's tamper-evidence values
  (protection level, journal digest, chain head, seal digest, signature and
  signer). The export itself is not covered by the seal or the signature.
- **An export of an encrypted trace is plaintext.** `export` says so on
  stderr: `warning: <trace> is encrypted, but this export is plaintext;
  protect or delete it accordingly`.

`export` runs the recorder's own structured redaction again: secret field
names as object keys, header-style pairs, argument lists, and JSON inside
strings, plus the built-in value patterns. A current recorder has already
applied these before the journal write, so for its traces the pass mostly
counts markers; for older traces it removes what was stored.

The document format, the `source` block, and the redaction report are
described in [redaction.md](redaction.md#premier-export).

## `diff`

```text
$ premier diff --help
Compare two traces by semantic event structure, ignoring generated identity noise

Usage: premier diff [OPTIONS] <BASELINE> <CURRENT>

Arguments:
  <BASELINE>  
  <CURRENT>   

Options:
      --json              Emit the complete structural comparison as JSON
      --key-file <PATH>   Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --allow-unverified  Compare finalized traces even though one fails `premier verify`
  -h, --help              Print help
```

Events are matched by a semantic key: kind, actor, and, for `tool.*` events,
the payload's `tool`, `name`, or `command` (for `approval.*`, its `operation`
or `action`). The n-th occurrence of a key in the baseline is paired with the
n-th in the current trace. Matched events are compared on `status`, `source`,
`actor_type`, `duration_ms`, and the flattened payload. Generated identity
(`event_id`, `trace_id`, span and correlation ids, timestamps) is ignored, and
so are provider-generated ids inside an adapter's `native` copy.

The text view prints the counts and one line per added, removed, or changed
event. `--json` prints the full comparison with
`format: "premier.semantic-diff.v1"`. The exit status is `0` whether or not
the traces differ.

## `replay`

```text
$ premier replay --help
Replay recorded evidence timing only; this never re-executes the traced command. A recorded gap longer than 10 seconds is replayed as 10 seconds

Usage: premier replay [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
      --key-file <PATH>   Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --speed <SPEED>     Playback speed multiplier (for example 2 replays twice as fast) [default: 1]
      --no-sleep          Emit evidence immediately while preserving recorded order
      --allow-unverified  Replay a finalized trace even though it fails `premier verify`
  -h, --help              Print help
```

Prints each recorded event as one JSON line on stdout, in sequence order,
sleeping between events for the recorded gap divided by `--speed`. It runs no
command, tool, or model. `--speed` must be a positive finite number.

**Gap cap.** A recorded gap longer than 10 seconds is replayed as 10 seconds.
The cap is applied before `--speed`, so at `--speed 2` the longest wait is 5
seconds. Timestamps are recorded evidence, not trusted input: a wrong clock
must not make a replay sleep for hours.

## `--allow-unverified`

`query`, `export`, `diff`, and `replay` run the same checks as `premier verify`
(without `--public-key`) before they read a trace:

| Trace state | Behaviour |
| --- | --- |
| Finalized and verifies | Read normally. |
| Not finalized (still recording, or abandoned) | Read, with `note: <trace> is not finalized (still recording or interrupted); its events are unverified and may be incomplete` on stderr. |
| Finalized but fails verification | Refused, exit `1`: `trace <path> failed verification: <reason>. Its evidence may have been altered or truncated; pass --allow-unverified to read it anyway`. |
| Finalized, fails verification, `--allow-unverified` given | A warning on stderr, then the command tries to read the trace. A journal that is damaged beyond decoding still fails. |

`diff` checks both traces. `encrypt` and `sign` always require a trace that
verifies and have no override.

## `list`

```text
$ premier list --help
List traces in a directory

Usage: premier list [OPTIONS]

Options:
      --key-file <PATH>        Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --trace-dir <TRACE_DIR>  [default: .premier/traces]
  -h, --help                   Print help
```

Prints one line per trace, newest first: trace id, start time, and the run
name (or the command line when there is no name), followed by `[recording]`
or `[abandoned: ...]` for a trace that is not finalized. A missing directory
prints nothing and exits `0`.

An encrypted trace that cannot be opened is still listed, after the readable
ones, from the public part of its manifest. Its name and command are
encrypted, so the directory name stands in for them:

```text
$ premier list --trace-dir traces
01a130a6-5150-7631-b059-e864addfee77  2026-10-12 15:06:08.597934 UTC  sh -c echo hi
01a130a6-51e5-7a93-bfc3-9903396ca127  2026-10-12T15:06:08.744965Z  enc2.atrace  [encrypted: key required]
```

`[encrypted: key required]` means no key file was configured. When one was
configured but does not open the trace, the bracket holds the reason instead,
for example `[encrypted: trace decryption failed: wrong key]`. Other
directories whose manifest cannot be read are skipped.

## `open`

```text
$ premier open --help
Open the local viewer, optionally focused on one trace

Usage: premier open [OPTIONS] [TRACE]

Arguments:
  [TRACE]  

Options:
      --key-file <PATH>          Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --trace-dir <TRACE_DIR>    [default: .premier/traces]
      --viewer-dir <VIEWER_DIR>  Optional disk viewer (for local UI development). Default: embedded viewer
      --bind <BIND>              [default: 127.0.0.1:4317]
      --no-assistant             Do not expose the local assistant (also: PREMIER_DISABLE_ASSISTANT=1)
  -h, --help                     Print help
```

Starts the viewer server, prints its URL, and opens a browser. It runs until
interrupted.

- `premier open` serves every trace in `--trace-dir`.
- `premier open <trace>` serves only that trace. Other traces in the same
  directory are not listed and cannot be fetched.
- `open` has no authentication options, so `--bind` must be a loopback
  address. Use `serve` for anything else.
- `--no-assistant` or `PREMIER_DISABLE_ASSISTANT` removes the local assistant;
  see [security.md](security.md#the-local-assistant).
- Encrypted traces are readable only when the server was started with their
  key (`--key-file` or `PREMIER_TRACE_KEY_FILE`). Otherwise they are listed as
  locked; see [Viewer states](#viewer-states).

## `serve`

```text
$ premier serve --help
Serve the viewer locally or to an authenticated team

Usage: premier serve [OPTIONS]

Options:
      --key-file <PATH>            Trace encryption key file, used to write new traces encrypted and to read encrypted ones. The file holds one 256-bit key as exactly 64 hex characters (for example from `openssl rand -hex 32`) and must be readable only by its owner (mode 0600) [env: PREMIER_TRACE_KEY_FILE=]
      --trace-dir <TRACE_DIR>      [default: .premier/traces]
      --viewer-dir <VIEWER_DIR>    Optional disk viewer (for local UI development). Default: embedded viewer
      --bind <BIND>                [default: 127.0.0.1:4317]
      --password <PASSWORD>        [env: PREMIER_PASSWORD]
      --auth-config <AUTH_CONFIG>  JSON file containing SHA-256 hashed bearer tokens, tenant ownership, and scopes [env: PREMIER_AUTH_CONFIG=]
      --tls-cert <TLS_CERT>        PEM certificate chain for native HTTPS. Must be paired with --tls-key [env: PREMIER_TLS_CERT=]
      --tls-key <TLS_KEY>          PEM private key for native HTTPS. Must be paired with --tls-cert [env: PREMIER_TLS_KEY=]
      --no-assistant               Do not expose the local assistant (also: PREMIER_DISABLE_ASSISTANT=1)
  -h, --help                       Print help
```

Like `open`, without launching a browser, and with authentication and TLS.
The rules for passwords, bearer tokens, scopes, non-loopback binds, and TLS
are in [security.md](security.md#the-viewer-server).

`--viewer-dir` (on `record`, `open`, and `serve`) serves the viewer from a
directory containing `index.html` instead of the copy embedded in the binary.
A binary built without the viewer bundle refuses to serve unless
`--viewer-dir` is given.

## The viewer API

`open`, `serve`, and `record --open` serve a read-only JSON API under `/api`
next to the viewer UI. The viewer is its only first-party client; the routes
below are what it uses. Authentication, scopes, and the Host and cross-origin
checks are described in [security.md](security.md#the-viewer-server).

| Route | Returns |
| --- | --- |
| `GET /api/health` | Server status. |
| `GET /api/assistants` | The local assistant providers and whether each is available. |
| `GET /api/traces` | One entry per trace: the manifest fields plus a summary and the integrity fields below. |
| `GET /api/traces/{trace_id}` | The same for one trace. |
| `GET /api/traces/{trace_id}/events` | The trace's events. See [Paged events](#paged-events). |
| `GET /api/traces/{trace_id}/stream` | A server-sent event stream. See [Event stream](#event-stream). |

### Integrity fields

Every trace entry carries:

| Field | Values |
| --- | --- |
| `integrity` | `live` (being recorded), `abandoned` (not finalized and the recorder is gone), `verified` (finalized and passed every check its format version supports), `invalid` (failed verification, or its manifest cannot be read), `locked` (encrypted and the server has no key that opens it). |
| `integrity_detail` | A sentence for `abandoned`, `invalid`, and `locked`. Absent otherwise. |
| `integrity_protection` | Present for `verified` only: `digest_only` (version 1), `sealed` (version 2, unsigned), or `signed`. |
| `integrity_signer` | Present for `signed` only: the fingerprint of the public key stored in the trace. |

The server has no list of trusted keys, so `signed` means "carries a valid
signature by the key stored in the trace", the same thing `premier verify`
without `--public-key` reports as `consistent: ... signed by an unknown key`.
`verified` with `integrity_protection: "sealed"` is a trace that is only
internally consistent.

For an abandoned trace, `integrity_detail` gives the recover command with the
trace directory's own name only, for example
`` Run `premier recover --force abandoned.atrace` to finalize this trace. ``
The API does not reveal where the server keeps its traces. The CLI prints the
real path.

A locked trace is listed with `trace_id` `locked:<directory name>`, the public
`encryption` envelope, and an `integrity_detail` that says whether no key was
configured or the configured key does not open it.

### Paged events

`GET /api/traces/{trace_id}/events` with no query string returns every event.
With `after_sequence`, `limit`, or both it returns one page: the events whose
`sequence` is greater than `after_sequence` (default `0`), at most `limit` of
them (default `500`). A `limit` of `0` or above `10000` is rejected with
`400`.

The viewer loads a trace this way, 5,000 events per page, and shows the first
page as soon as it arrives. While later pages load, the timeline heading shows
`Loading <n> of <total> events` (the total is omitted for a run that is still
being recorded).

### Event stream

`GET /api/traces/{trace_id}/stream` tails a trace as server-sent events:

| Event | Data | Sent |
| --- | --- | --- |
| `trace.event` | One event. | For each event in the journal, then for each new event as it is recorded. |
| `trace.complete` | The trace entry, as `GET /api/traces/{trace_id}` returns it. | Once, when the trace is finalized by its recorder or by `premier recover`. The stream then closes. |
| `trace.abandoned` | The trace entry, with `integrity: "abandoned"`. | Once, when the recorder is gone and the trace is not finalized. The stream then closes. |

- `?after_sequence=<n>` skips events whose sequence is `n` or lower, so a
  client that has already paged the journal does not receive it a second
  time. The viewer resumes after the last sequence it loaded.
- The journal is polled every 250 ms. `trace.abandoned` is sent only after two
  consecutive polls classify the trace as abandoned, so a recorder that has
  not written its lease yet is not reported as gone.
- A stream on a trace whose recorder is alive stays open. Keep-alive comments
  are sent every 10 seconds.

### Errors

| Status | When |
| --- | --- |
| `400` | The trace id contains `/` or `\`, or is `.` or `..`; or `limit` is out of range. |
| `404` | No served trace has that id, the trace belongs to another tenant, or the trace directory does not exist. |
| `500` | The trace directory exists but cannot be read. The error message is `cannot read the trace directory`; the path is logged on the server and not sent to the client. |

Error bodies are `{"error": "<message>"}`.

### Viewer states

| The viewer shows | When |
| --- | --- |
| `signed by <fingerprint>` | `integrity_protection` is `signed`. |
| `unsigned, self-consistent only` | `integrity_protection` is `sealed`. |
| `unsigned, v1 digest only` | `integrity_protection` is `digest_only`. |
| `integrity failed` | `integrity` is `invalid`. |
| An abandoned state with the recover command | `integrity` is `abandoned`, in the list or from a `trace.abandoned` event while the trace is open. |
| `Encrypted · key required` and a `Locked` badge in the trace list | `integrity` is `locked`. |

When the listed state of the open trace changes (it was recovered, finalized,
or is being recorded again), the viewer reloads its manifest and events and
keeps the selected event.
