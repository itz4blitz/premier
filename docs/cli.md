# `premier` command reference

This page describes the `premier` binary as built from this repository
(`crates/premier-cli`). The `--help` blocks are pasted from the binary.

```text
$ premier --help
Local-first agent trace recorder and viewer

Usage: premier <COMMAND>

Commands:
  record   Record a command and its terminal output into a portable .atrace directory
  demo     Generate a rich local multi-agent trace for product evaluation and onboarding
  emit     Emit a typed agent event to the active local collector (`PREMIER_COLLECTOR_*`)
  verify   Verify a finalized trace's digest, framing, event count, and identity
  recover  Safely finalize an abandoned active trace, discarding only a torn trailing frame
  claim    Atomically claim a legacy/local trace for a tenant
  encrypt  Atomically encrypt a finalized trace, or rotate it to a new master key
  query    Filter local trace evidence without starting the viewer
  export   Export portable JSON evidence with common secret fields recursively redacted. The `redaction` block reports the active rules and what was removed
  diff     Compare two traces by semantic event structure, ignoring generated identity noise
  replay   Replay recorded evidence timing only; this never re-executes the traced command
  list     List traces in a directory
  open     Open the local viewer, optionally focused on one trace
  serve    Serve the viewer locally or to an authenticated team
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Conventions

- A trace is a directory, by convention named `*.atrace`. The default trace
  directory is `.premier/traces` relative to the current directory.
- Exit codes, for every command except `record`:

  | Code | Meaning |
  | --- | --- |
  | `0` | Success. |
  | `1` | The command failed. The reason is printed to stderr as `Error: ...`. |
  | `2` | Invalid command line (unknown flag, missing argument, out-of-range value). |

  `record` returns the recorded command's own status; see
  [Exit status](#exit-status). It uses `1` and `2` as above only when it fails
  before the command starts (for example an invalid `--redact-regex`).
- Environment variables read by the CLI:

  | Variable | Used by | Meaning |
  | --- | --- | --- |
  | `PREMIER_TRACE_KEY_FILE` | every command that writes or reads a trace | Path to the encryption key file. See [security.md](security.md#encryption-at-rest). |
  | `PREMIER_STOP_GRACE_MS` | `record` | Milliseconds a child may outlive a forwarded SIGTERM, SIGHUP, or SIGQUIT before it is killed. Default `10000`. |
  | `PREMIER_COLLECTOR_URL`, `PREMIER_COLLECTOR_TOKEN` | `emit` | Collector endpoint and bearer token. `record` sets them for the recorded process. |
  | `PREMIER_EMIT_TIMEOUT` | `emit` | Seconds to wait for the collector. Default `10`. |
  | `PREMIER_DISABLE_ASSISTANT` | `open`, `serve`, `record --open` | Any value other than empty, `0`, `false`, `no`, or `off` disables the local assistant. |
  | `PREMIER_PASSWORD`, `PREMIER_AUTH_CONFIG`, `PREMIER_TLS_CERT`, `PREMIER_TLS_KEY` | `serve` | Environment forms of `--password`, `--auth-config`, `--tls-cert`, `--tls-key`. |

  `record` also sets `PREMIER_TRACE_ID` for the recorded process.

## `record`

```text
$ premier record --help
Record a command and its terminal output into a portable .atrace directory

Usage: premier record [OPTIONS] <COMMAND>...

Arguments:
  <COMMAND>...  

Options:
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
          Regex to redact from persisted terminal output, event payloads, and the recorded command line (terminal display stays raw). Regex rules are line-scoped: in terminal output a match never spans a line break, so write one rule per line of a multi-line secret. A line longer than 256 KiB is stored in pieces, and only a match up to 16 KiB is guaranteed across such a cut. A partial line (such as a prompt) is stored after 1 second without output, so a match the output pauses inside can be split; use --redact-literal for exact secrets
      --no-default-secret-patterns
          Do not apply the built-in secret value patterns (API keys, bearer credentials, URL passwords, private key blocks, JWTs) to structured event payloads and the recorded command line
      --redact-known-secrets
          Also apply the built-in secret value patterns to persisted terminal output, which is otherwise stored raw unless a --redact-literal or --redact-regex rule matches
  -h, --help
          Print help
```

```sh
premier record -- npm test
premier record --name "nightly eval" -o runs/nightly.atrace -- ./agent run
```

Everything after `--` is the command. Options must come before it.

| Option | Notes |
| --- | --- |
| `-o, --output` | Trace directory to create. Default `.premier/traces/trace-<unix-milliseconds>.atrace`. Parent directories are created. Recording fails if the path already exists. |
| `--name` | Run name. The redaction rules apply to it. |
| `--tenant` | 1-128 ASCII letters, digits, `.`, `_`, or `-`. Default `local`. `--open` is rejected for any tenant other than `local`. |
| `--open` | After the trace is finalized, serve the viewer for this one trace on `--bind` and open a browser. Skipped when the recorder received a stop signal. `--viewer-dir` and `--bind` only matter with `--open`. |
| `--pty` | See [PTY capture](#pty-capture). |
| `--adapter` | `auto`, `none`, `codex`, `claude`, `gemini`, `grok`, `opencode`, `kimi`, or `droid`. See [adapters.md](adapters.md). |
| `--redact-*`, `--no-default-secret-patterns` | Repeatable where they take a value. See [redaction.md](redaction.md). |

What `record` does:

1. Creates the trace directory and starts a loopback HTTP collector on a random
   port (see [collector.md](collector.md)).
2. Starts the command with `PREMIER_TRACE_ID`, `PREMIER_COLLECTOR_URL`, and
   `PREMIER_COLLECTOR_TOKEN` added to its environment. Standard input is
   inherited.
3. Copies the command's stdout and stderr to its own stdout and stderr
   unchanged, and stores them as `process.stdout` / `process.stderr` events. If
   the recorder's own stdout or stderr is closed (for example
   `premier record -- cmd | head`), mirroring stops and capture continues.
4. When the command exits, appends `process.exit`, finalizes the trace, and
   prints the trace id and path to stderr.

A descendant that keeps the output pipe open does not block finalization.
After the command exits, the recorder keeps reading until the stream has been
quiet for 250 ms, or for at most 5 seconds, then finalizes and sets
`output_open_at_exit: true` on `process.exit`.

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
trace 01a13088-cfe5-7623-967a-530d71f4c1cd → missing.atrace
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
  error.

## `demo`

```text
$ premier demo --help
Generate a rich local multi-agent trace for product evaluation and onboarding

Usage: premier demo [OPTIONS]

Options:
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
Verify a finalized trace's digest, framing, event count, and identity

Usage: premier verify <TRACE>

Arguments:
  <TRACE>  

Options:
  -h, --help  Print help
```

Checks, in order:

1. The manifest reads and has format version 1 (and, for an encrypted trace,
   decrypts with the configured key).
2. The manifest names the canonical journal path, and the SHA-256 of the
   compressed journal file equals the digest in the manifest.
3. Every frame decodes.
4. The number of events equals the count in the manifest.
5. Every event carries the manifest's trace id.
6. Sequences are contiguous from 1, and event ids are non-empty and unique.

| Outcome | Exit | Output |
| --- | --- | --- |
| Verified | `0` | `verified <trace id> (<n> events, <m> semantic diagnostics)` on stdout, then one `warning <code> at sequence <n>: <message>` line per diagnostic |
| Still being recorded | `1` | `Error: trace is not finalized (still recording)` |
| Abandoned | `1` | `Error: trace is not finalized (abandoned: the recorder is no longer running — run ...)`, naming the `premier recover` command to run |
| A check failed | `1` | `Error: journal digest mismatch`, `Error: event count mismatch`, and so on |

Diagnostics are warnings about the recorded events (see
[events.md](events.md#lifecycle-validation)). They do not fail verification.

What verification does and does not prove is covered in
[security.md](security.md#what-verification-proves).

## Abandoned traces and `recover`

```text
$ premier recover --help
Safely finalize an abandoned active trace, discarding only a torn trailing frame

Usage: premier recover [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
      --stale-after-seconds <STALE_AFTER_SECONDS>
          Minimum journal idle time required before recovery [default: 300]
      --force
          Recover even when the journal was modified recently
  -h, --help
          Print help
```

While it runs, a recorder keeps a lease file, `recorder.lease`, in the trace
directory. The file holds the recorder's process id and is rewritten every 2
seconds. A trace with no finalized journal is classified from that lease:

| Lease | State | `list` shows |
| --- | --- | --- |
| Names a live process and was written less than 300 s ago | recording | `[recording]` |
| Names a process that no longer exists | abandoned | `[abandoned: ...]` with the command `premier recover <trace>` |
| Missing or unreadable, or names a live process but is 300 s or more old (the id was probably reused) | abandoned | `[abandoned: ...]` with `premier recover <trace>`, or `premier recover --force <trace>` while the journal or lease was modified less than 300 s ago |

A recorder that was killed outright (SIGKILL, power loss, a crash) leaves an
abandoned trace. `premier verify` refuses it and prints the recover command.
The viewer shows it as abandoned.

`premier recover <trace>` decides as follows:

1. A finalized trace is refused: `trace is already finalized`.
2. With `--force`, recovery proceeds.
3. If the lease names a live recorder (same rule as above), recovery is
   refused: `trace is still being recorded by process <pid>; ...`.
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

```text
$ premier list --trace-dir .
01a13085-79bc-7402-8395-02638622647a  2026-10-12 14:30:16.255459 UTC  sh -c echo started; sleep 4  [abandoned: the recorder is no longer running — run `premier recover ./ab.atrace`]
$ premier recover ab.atrace
recovered 01a13085-79bc-7402-8395-02638622647a (3 events, exit 130)
```

`--force` on a trace whose recorder is still running finalizes it underneath
that recorder. Stop the recorder first.

## `claim`

```text
$ premier claim --help
Atomically claim a legacy/local trace for a tenant

Usage: premier claim --tenant <TENANT> <TRACE>

Arguments:
  <TRACE>  

Options:
      --tenant <TENANT>  
  -h, --help             Print help
```

Changes the manifest's `tenant_id` from `local` to `--tenant`. Only a trace
owned by `local` can be claimed, so a trace can be claimed once. Tenant ids
are 1-128 ASCII letters, digits, `.`, `_`, or `-`. Tenants matter to
`premier serve --auth-config`; see [security.md](security.md#authentication-and-scopes).

## `encrypt`

```text
$ premier encrypt --help
Atomically encrypt a finalized trace, or rotate it to a new master key

Usage: premier encrypt --new-key-file <PATH> <TRACE>

Arguments:
  <TRACE>  

Options:
      --new-key-file <PATH>  
  -h, --help                 Print help
```

See [security.md](security.md#encryption-at-rest).

## `query`

```text
$ premier query --help
Filter local trace evidence without starting the viewer

Usage: premier query [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
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
  stdout and `<n> matched; <m> returned` on stderr.
- `--json` prints `{"matched", "returned", "truncated", "events"}`. Events are
  printed as stored; `query` applies no redaction.

## `export`

```text
$ premier export --help
Export portable JSON evidence with common secret fields recursively redacted. The `redaction` block reports the active rules and what was removed

Usage: premier export [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
  -o, --output <OUTPUT>             Destination JSON file. Omit to write JSON to stdout
      --no-default-secret-patterns  Do not apply the built-in secret value patterns (API keys, bearer credentials, URL passwords, private key blocks, JWTs) to structured event payloads and the recorded command line
      --redact-known-secrets        Also apply the built-in secret value patterns to captured terminal output, which is otherwise exported as recorded
      --allow-unverified            Export a finalized trace even though it fails `premier verify`
  -h, --help                        Print help
```

Writes one JSON document with `format: "premier.portable-evidence.v1"`, a
`redaction` report, the manifest, and every event with its payload decoded.
With `--output` the file is written through a temporary file and a rename.
The document format and the redaction report are described in
[redaction.md](redaction.md#premier-export).

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
Replay recorded evidence timing only; this never re-executes the traced command

Usage: premier replay [OPTIONS] <TRACE>

Arguments:
  <TRACE>  

Options:
      --speed <SPEED>     Playback speed multiplier (for example 2 replays twice as fast) [default: 1]
      --no-sleep          Emit evidence immediately while preserving recorded order
      --allow-unverified  Replay a finalized trace even though it fails `premier verify`
  -h, --help              Print help
```

Prints each recorded event as one JSON line on stdout, in sequence order,
sleeping between events for the recorded gap divided by `--speed`. It runs no
command, tool, or model. `--speed` must be a positive finite number.

## `--allow-unverified`

`query`, `export`, `diff`, and `replay` run the same checks as `premier verify`
before they read a trace:

| Trace state | Behaviour |
| --- | --- |
| Finalized and verifies | Read normally. |
| Not finalized (still recording, or abandoned) | Read, with `note: <trace> is not finalized (still recording or interrupted); its events are unverified and may be incomplete` on stderr. |
| Finalized but fails verification | Refused, exit `1`: `trace <path> failed verification: <reason>. Its evidence may have been altered or truncated; pass --allow-unverified to read it anyway`. |
| Finalized, fails verification, `--allow-unverified` given | A warning on stderr, then the command tries to read the trace. A journal that is damaged beyond decoding still fails. |

`diff` checks both traces. `encrypt` always requires a trace that verifies
and has no override.

## `list`

```text
$ premier list --help
List traces in a directory

Usage: premier list [OPTIONS]

Options:
      --trace-dir <TRACE_DIR>  [default: .premier/traces]
  -h, --help                   Print help
```

Prints one line per trace, newest first: trace id, start time, and the run
name (or the command line when there is no name), followed by `[recording]`
or `[abandoned: ...]` for a trace that is not finalized. Directories whose
manifest cannot be read are skipped; that includes encrypted traces when
`PREMIER_TRACE_KEY_FILE` is not set. A missing directory prints nothing and
exits `0`.

## `open`

```text
$ premier open --help
Open the local viewer, optionally focused on one trace

Usage: premier open [OPTIONS] [TRACE]

Arguments:
  [TRACE]  

Options:
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

## `serve`

```text
$ premier serve --help
Serve the viewer locally or to an authenticated team

Usage: premier serve [OPTIONS]

Options:
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
