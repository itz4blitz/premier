# Changelog

Changes a user of the `premier` CLI, the viewer, or `@premierstudio/trace`
would notice. Entries marked **Breaking** change behaviour that scripts or
integrations may depend on.

## Unreleased

### Added

- `premier record` ends with a `protection:` line on stderr saying whether
  the trace was written encrypted (with the key id) and whether it was signed
  (with the signer's fingerprint), so a mistyped key variable no longer
  passes for an encrypted recording.
- `premier keygen --encryption <path>` writes a trace encryption key file
  (256 bits from the system random number generator, mode `0600`) for
  `--key-file`.
- `premier record --pty` follows resizes of the recorder's terminal: the PTY
  is resized on SIGWINCH and a `process.resize` event records the new size.
- `premier record --pty` with redirected stdin now ends the command's input
  when the pipe or file ends (and no longer echoes forwarded input into the
  captured output), so `printf 'x\n' | premier record --pty -- cat` finishes.
- Captured output that is not valid UTF-8 is marked: the event gets
  `lossy: true` and `replaced_sequences`. The stored text still has U+FFFD
  in place of each invalid sequence, and the raw bytes are not kept.
- `premier open`, `premier serve`, and the viewer of `record --open` stop on
  Ctrl-C and SIGTERM: in-flight requests finish, open connections are dropped
  after 2 seconds, and the exit status is `0`.
- `premier list` shows every trace it cannot open, with the reason:
  `[needs a newer premier: format version N]` or `[unreadable: ...]`, beside
  the existing `[encrypted: ...]`. The viewer API reports a trace in a later
  format as `integrity: "unsupported"` instead of as damaged.
- `premier recover` on an already finalized trace removes the working files
  an interrupted finalization left behind, once the trace verifies. It can
  also be repeated after being interrupted itself, and continues from the
  compressed journal when the active journal is gone.
- `premier encrypt` puts right what an earlier `encrypt` killed during its
  final swap left behind: it moves the trace back when nothing is at its
  path and removes the superseded (possibly plaintext) copy.
- The collector records the first request of a recording that arrives
  without its token as a `collector.unauthorized` event, and delays each
  further refusal in a row (100 ms steps, at most 1 second).
- `premier verify` notes when a trace was finalized by `premier recover`.
- Manifest fields a build does not know are kept when a command rewrites the
  manifest, and are covered by the seal.

- `premier verify --live` checks an unfinalized trace's frames and hash chain
  without modifying it.
- `premier recover --sign-key` signs a recovered trace.
- `premier recover` salvages the valid prefix of a damaged active journal and
  records what it discarded (`seal.discarded_bytes`, `seal.discarded_frames`,
  a `journal.recovery_discarded` diagnostic).
- Streaming readers: `verify`, `query`, `export`, `replay`, finalization, and
  the viewer server no longer load a whole journal into memory. Finalized
  journals are written as independently readable blocks, and the viewer API
  pages through them without rescanning from the start.
- **Trace format version 2: event hash chain, manifest seal, optional
  signature.** Every event names the hash of the event before it, and the
  manifest carries a seal over all of its fields and the chain head.
  `premier verify` checks both. A trace can also be signed with a local
  Ed25519 key. An unsigned trace is only self-consistent: whoever can write to
  it can rebuild the chain and the seal. See
  [docs/trace-format.md](docs/trace-format.md) and
  [docs/security.md](docs/security.md#what-verification-proves).
- `premier keygen <path>` writes an Ed25519 private key (mode `0600`) and
  `<path>.pub`, and prints the public key and its fingerprint.
- `premier sign <trace> --sign-key <path>` signs or re-signs a finalized
  trace that verifies.
- `premier record --sign-key <path>` and `PREMIER_SIGN_KEY_FILE` sign a trace
  when it is finalized. `PREMIER_SIGN_KEY_FILE` also applies to
  `premier recover`, `premier claim`, and `premier encrypt`.
- `premier verify --public-key <path-or-hex>` requires a valid signature by
  that key.
- `premier encrypt --sign-key <path>` re-signs the re-sealed trace. Without a
  signing key, `encrypt` and `claim` drop an existing signature and print a
  warning.
- `premier export` output has a `source` block with the source trace's
  format version, protection level, journal digest, chain head, seal digest,
  signature, and signer.
- Viewer API: `integrity_protection` (`digest_only`, `sealed`, `signed`) and
  `integrity_signer` on every verified trace. The viewer labels a verified
  trace `signed by <fingerprint>`, `unsigned, self-consistent only`, or
  `unsigned, v1 digest only`.
- **Global `--key-file <path>` option** on every subcommand, the flag form of
  `PREMIER_TRACE_KEY_FILE`. The flag wins when both are set.
- `premier list` shows an encrypted trace it cannot open, as
  `[encrypted: key required]` or `[encrypted: <reason>]`, instead of skipping
  it. The viewer API reports such a trace as `integrity: "locked"`, and the
  viewer shows it as locked rather than damaged.
- `premier record --redact-regex-multiline <regex>`: a redaction regex that
  may match across line breaks, matched over a 16 KiB sliding window in
  terminal output. The manifest records the rule count as
  `redaction.terminal_multiline_regex_count`.
- `PREMIER_REDACTION_IDLE_FLUSH_MS` sets how long a stream must be quiet
  before output held for a redaction rule is stored (default 1000).
- Viewer API: the event stream ends with one terminal event,
  `trace.complete` or the new `trace.abandoned`, and accepts
  `?after_sequence=<n>` to resume after events the client already has.
- Viewer: events load in pages of 5,000 with a progress indicator, the live
  stream resumes after the last loaded sequence, an open trace is reloaded
  when its state changes (recovered, finalized, recording again), and a run
  whose command could not be started is named as such.
- Adapters: `parent_event_id` and `links` resolved to stored event ids;
  synthesized `agent.spawn` and `agent.result` events for subagents, marked
  `payload.synthesized: true`; `payload.lifecycle`, `payload.session_id`, and
  `payload.native_timestamp`. See [docs/adapters.md](docs/adapters.md).
- **Record-time redaction of structured shapes.** Secret names are now
  recognised before the journal write in header-style pairs
  (`{"name": "Authorization", "value": ...}`, `["Cookie", ...]`), in argument
  lists inside payloads, and in JSON held inside a string, including each
  JSON-object line of a multi-line string. `premier export` previously did
  this for the exported copy only; it now shares the recorder's code and
  repeats the pass for older traces.
- More secret field names: `auth`, `jwt`, `passphrase`, `secret_key`,
  `signing_key`, `private_key_pem`, `access_key`, and `access_key_id`. Names
  match as a suffix, so `basic_auth` and `x-auth` are redacted while `author`
  and `auth_method` are not.
- Built-in value pattern `url-query-credentials`: the value of a URL query
  parameter named `token`, `access_token`, `api_key`, `client_secret`,
  `password`, `signature`, `X-Amz-Signature`, and similar.
- Command-line redaction of `curl -u user:<password>` / `--user` /
  `--proxy-user` (the user name is kept) and of `-p<password>` after `mysql`,
  `mysqldump`, `mysqladmin`, `mysqlimport`, `mysqlshow`, `mysqlcheck`,
  `mariadb`, or `mariadb-dump`.
- The recorder always redacts the run's own `PREMIER_COLLECTOR_TOKEN` value
  from everything it stores. The manifest names the rule in the new
  `redaction.implicit_rules` (`["collector-token"]`).
- `--redact-literal`, `--redact-regex`, and `--redact-regex-multiline` also
  apply to the event fields outside the payload (`kind`, `source`,
  `actor_id`, `actor_type`, `span_id`, `parent_span_id`, `correlation_id`,
  `status`).
- `--adapter auto` finds the agent behind `env`, `npx`, `bunx`, `pnpx`,
  `pnpm dlx`, `yarn dlx`, and `sh -c` with one simple command.
- `premier record --pty` prints a one-line note on stderr when `--adapter
  auto` would have activated an adapter, since PTY capture records terminal
  output only.
- Adapters: `usage.input_tokens_details.cache_creation_tokens`;
  `payload.usage_reported_on`; `agent.message` events with `payload.role:
  "user"` for user lines; Codex `file_change` and `web_search` items as tool
  events with `payload.paths` / `payload.query`, and `reasoning` items as
  `model.response` with `payload.reasoning: true`; an `approval.decision`
  with status `denied` and `payload.synthesized: true` for each entry of
  Claude Code's `permission_denials` (it has no `approval.request`, so the
  trace reports `missing_lifecycle_start` for it).
- Viewer: the masked export uses the recorder's secret field names and masks
  every built-in value pattern shape.
- [docs/trace-format.md](docs/trace-format.md), a
  [documentation index](docs/README.md), and
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **Built-in secret value patterns.** Values shaped like well-known
  credentials (API keys, bearer credentials, URL passwords, credentials in a
  URL query string, private key blocks, JWTs, GitHub, AWS, and Slack tokens)
  are redacted from structured
  event payloads and the recorded command line by default.
  `premier record --no-default-secret-patterns` turns them off;
  `--redact-known-secrets` also applies them to stored terminal output. The
  manifest's `redaction` block records which were active. See
  [docs/redaction.md](docs/redaction.md).
- `premier export --no-default-secret-patterns` and `--redact-known-secrets`,
  and a `redaction.rules` / `redaction.redacted` report of the rules that ran
  and what they removed.
- `--allow-unverified` on `premier query`, `export`, `diff`, and `replay`.
- `--no-assistant` on `premier open` and `premier serve`, and
  `PREMIER_DISABLE_ASSISTANT`, to remove the local assistant.
- The recorder now handles SIGHUP and SIGQUIT as well as SIGINT and SIGTERM,
  and finalizes the trace for each. `PREMIER_STOP_GRACE_MS` sets how long a
  command may outlive a forwarded SIGTERM, SIGHUP, or SIGQUIT (default 10 s).
- A command that cannot be started now leaves a finalized trace with a
  `process.spawn_failed` event, and `premier record` exits `127` (not found)
  or `126` (not executable).
- **Abandoned traces.** `premier list`, `premier verify`, and the viewer
  distinguish a trace whose recorder is gone from one still being recorded,
  and print the `premier recover` command to run.
- `process.exit` records `recorder_signal`, `recorder_signal_name`, and
  `killed_by_recorder` when the recorder itself was told to stop, and
  `output_open_at_exit` when a descendant still held the output stream.
- A `journal.write_failed` diagnostic when events could not be written.
- `PREMIER_EMIT_TIMEOUT` (seconds, default 10) for `premier emit` and
  `sdk/shell/premier-emit.sh`.
- SDK: `premier.delegation`, `premier.result`, `premier.join`,
  `premier.message`, and `premier.approvalDecision` helpers; `childOf`; and
  the `timeoutMs`, `signal`, and `onError` options.
- Adapters: normalized `tool`, `command`, `model`, `usage.*`, and
  `parent_actor` payload fields; subagent actors from `parent_tool_use_id`;
  `native_truncated` on oversized lines. See
  [docs/adapters.md](docs/adapters.md).
- Viewer: navigation by span and link, search by event and span id, and a
  masked export that states it is best effort and unverified.
- Reference documentation under `docs/`.

### Changed

- **Default trace directory name.** `premier record` without `--output` now
  writes `.premier/traces/trace-<unix-milliseconds>-<8 random hex digits>.atrace`
  (was `trace-<unix-milliseconds>.atrace`), and every trace directory is
  created exclusively, so recorders started in the same instant can no
  longer end up in one directory.
- **Collector request bodies are checked more strictly.** A body that is not
  a JSON object is rejected with `400` (an array used to be read
  positionally), and so is an unknown top-level field (it used to be
  ignored). `trace_id` and `run`, which the SDKs send, are accepted; a
  `trace_id` naming another trace is rejected with `409`.
- The collector token is 256 bits from the system random number generator
  (64 hex characters), no longer a time-ordered UUID from the generator that
  also produces the public event ids.
- `premier emit --json` together with `--kind`, `--actor`, or another field
  option is a usage error. The options used to be ignored.
- `premier recover` uses the exit status the recorder journaled
  (`process.exit`) when the kept events hold it, instead of always stamping
  `interrupted` / `130`. The manifest's `ended_at` is the time the abandoned
  recording was last written to, not the time of the recovery; the
  `session.interrupted` payload gains `exit_recorded` and
  `last_activity_at`.
- `premier claim` refuses a trace that is not finalized. A claim made while
  the recorder was running reported success and was undone when the recorder
  finalized.
- `premier demo --output` refuses to replace a trace that is being recorded.
- `premier verify` and the viewer API report the diagnostics of the reading
  build's validator over the events, keeping only the `journal.*` entries
  from the manifest, instead of the list stored at finalization.
- Lifecycle validation pairs a finish with the start it names
  (`parent_event_id`, `links`), never with a start recorded after it, and
  otherwise with the most recent start still open rather than the first
  one. A synthesized `approval.decision` (`payload.synthesized: true`) no
  longer raises `missing_lifecycle_start`. A status is compared without
  surrounding whitespace.
- `premier replay --speed` must be at least `0.001`.
- `premier list` prints the start time of a trace it cannot open in the same
  form as every other row.
- A bearer credential's `tenant_id` may no longer contain `@`, matching the
  rule for trace tenants.
- Viewer API: an unclassified server error is answered with
  `{"error": "internal error; see the premier server log"}`; the detail is
  logged, not sent. A collector journal failure is answered with
  `the event could not be recorded`.

- **Breaking:** in `premier export` output the `redaction` block now follows
  `events`.
- **Breaking:** a trace recovered with discarded data carries seal fields that
  earlier builds of this branch do not accept.
- A truncated finalized journal is an error in every reader instead of reading
  as fewer events.
- **Breaking: new traces are written in format version 2.** The manifest has
  `format_version: 2` and a `seal`, and every event has a `prev_hash`. This
  version reads and verifies version 1 traces (reported as `v1: digest
  only`) and does not upgrade them. An older `premier` cannot read a version
  2 trace.
- **Breaking: `premier verify` output wording.** The success line no longer
  starts with `verified <trace id>`. It starts with `verified: chain and seal
  valid, signed by the supplied key <fingerprint>:` only for a signature by
  the key given with `--public-key`, and otherwise with `consistent: chain
  and seal valid, signed by an unknown key <fingerprint>:`, `consistent:
  chain and seal valid, unsigned:`, or `consistent (v1: digest only):`,
  followed by a `note:` line. A failed check is now reported as `Error:
  invalid: <trace> failed verification` with the reason under `Caused by:`.
  Scripts that match the old text need updating; the exit status is
  unchanged (`0` on success, `1` on failure). `verify` now also fails for a
  broken event chain or a manifest field edited after finalization.
- **Breaking: the collector validates every field.** `kind`, `source`, and
  `actor_type` accept only ASCII letters, digits, `.`, `_`, `:`, and `-`, up
  to 128 bytes. `actor_id`, `span_id`, `parent_span_id`, `correlation_id`,
  `status`, `parent_event_id`, and each `links` entry accept up to 256 bytes
  and no control characters. An empty `kind` or `source` is rejected. Events
  that were stored before are now rejected with `400`. See
  [docs/collector.md](docs/collector.md#field-rules).
- **Breaking: collector status codes.** A body over 2 MiB is rejected with
  `413` (was `400`). An empty or blank `kind` is rejected with `400` (was
  `500`). A body that does not arrive within 10 seconds is rejected with the
  new `408`.
- **Breaking: collector event timestamps are always the recorder's receipt
  time.** A `timestamp` sent by the producer no longer becomes the event's
  timestamp. It is kept as `payload.producer_timestamp`, must be RFC 3339
  (`400` otherwise), and requires the payload to be an object or absent
  (`400` otherwise). The collector's response now includes `prev_hash`.
- **Breaking: adapter event kinds.** Session start and turn start lines are
  `agent.turn` with `payload.lifecycle` (`session_start`, `turn_start`). A
  provider's final result line (`result`, `turn.completed`, `turn.failed`) is
  `agent.result` with `payload.lifecycle: "run_result"` and the run's usage
  and cost. Lines whose type names a `turn` are `agent.turn` /
  `agent.result`; they were `model.request` / `model.response`, so a Codex
  `turn.completed` moves from `model.response` to `agent.result`. OpenCode
  `text` parts are `model.response`.
  Classification matches whole words, so a type such as `pending` no longer
  counts as completed because it contains `end`. Session-level events use the
  session id as their `correlation_id`. Queries, diffs, and dashboards keyed
  on the old kinds need updating.
- **Breaking: adapter user lines and narrated tool calls.** A provider line
  whose role is `user` is an `agent.message` (it was a `model.response`),
  unless it carries tool results. An assistant message with both text and
  tool calls is a `model.response` followed by one tool event per call; the
  first call used to stand for the whole line.
- **Breaking: adapter usage.** `usage.total_tokens`, when the provider does
  not state a total, now also counts cache tokens the provider reports apart
  from input (Claude `cache_read_input_tokens` and
  `cache_creation_input_tokens`, OpenCode `cache.read` and `cache.write`).
  When a provider repeats one message's usage on several lines, only the
  first event carries `payload.usage`; the others carry
  `payload.usage_reported_on`. Sums over `payload.usage` change accordingly.
- **Breaking: a refused tool result has status `denied`.** An adapter
  `tool.result` whose provider status is `denied` or `rejected` was `error`.
  `declined` and `blocked` are now read as refusals too.
- `--adapter auto` ignores arguments after the command's own `--`, so
  `codex exec -- --json` is not treated as structured output.
- **Breaking: `premier query` prints an event without an actor as `-`**, not
  `root`.
- **Breaking: text output escapes control characters.** `verify`, `query`,
  `diff`, and `list` print control characters and invisible Unicode format
  characters in recorded text as escapes. JSON output is unchanged.
- **Breaking: `premier replay` caps a recorded gap at 10 seconds** (before
  `--speed` is applied).
- **Breaking: an encrypted trace without a key reports a different error:**
  `encrypted trace requires --key-file or PREMIER_TRACE_KEY_FILE`.
- **Breaking: the recorder lease format is `<pid> start=<n>`** (process id
  and process start time) where the platform reports a start time. A lease
  holding only a process id is still read. `premier recover` now refuses a
  suspended recorder however stale its lease is, and treats a reused process
  id as a dead recorder at once.
- `verify`, `query`, `export`, `diff`, `replay`, and `list` end quietly when
  their output pipe is closed (shell status `141`) instead of failing with a
  broken-pipe error.
- `premier export --output` creates the file with mode `0600`, and `export`
  warns on stderr that the export of an encrypted trace is plaintext.
- `premier record` no longer waits for collector clients when the command
  has exited: requests in flight get 2 seconds, then their connections are
  dropped.
- `premier recover` refuses an active journal whose event chain is broken and
  seals the recovered trace with `seal.recovered: true`. After a
  `recover --force` underneath a running recorder, that recorder no longer
  writes its lease back beside the finalized trace.
- The local assistant marks Codex unavailable unless `codex features list`,
  run with the assistant's overrides, reports `shell_tool` and
  `unified_exec` as `false`.
- Viewer API: the recover hint for an abandoned trace names the trace
  directory only, not its path on the server. A lookup against a missing
  trace directory answers `404`, and an unreadable one answers `500` with a
  fixed message, instead of a `500` that named the path.
- Adapter events take `duration_ms` from `stats.duration_ms` as well.
- The adapter fixtures are fuller, and their README states that they are
  hand-written, not captured from real runs.
- **Breaking: `query`, `export`, `diff`, and `replay` refuse a finalized trace
  that fails verification.** They exit `1` and name the failure. Pass
  `--allow-unverified` to read it anyway. A trace that is still being
  recorded is read as before, with a note on stderr. `premier encrypt` also
  refuses such a trace and has no override.
- **Breaking: the collector rejects recorder-owned events with `422`.** The
  kinds `session.start`, `session.interrupted`, and `process.*`, and the
  sources `premier`, `command`, `process`, `recorder`, `premier-recovery`, and
  `adapter.*`, can no longer be emitted by the recorded process. See
  [docs/collector.md](docs/collector.md#reserved-kinds-and-sources).
- **Breaking: `premier export` reports what it actually redacted.**
  `redaction.applied` used to be `true` on every export. It is now `true` only
  when that export replaced at least one value; `false` means the rules ran
  and found nothing left. `redaction.policy` has new text. Use
  `redaction.redacted` for counts.
- **Breaking: the assistant prompt uses the `[REDACTED]` marker.** It
  previously wrote `[REDACTED BY PREMIER]` and used its own field rules. It
  now shares the secret field names and value patterns used by
  `premier export`.
- **Breaking: SDK `emit` and the helpers no longer throw by default.** When
  the collector is unreachable, slow, or rejects the event they resolve to
  `null`, and report the failure to `onError` or once through `console.warn`.
  Requests time out after 5 seconds. Pass `{ required: true }` to get the
  throwing behaviour back.
- **Breaking: SDK helper positional arguments win over `extra`.** A helper's
  `kind`, `actor`, and `payload` can no longer be overridden by `extra.kind`,
  `extra.actor_id`, or `extra.payload`, and an `undefined` value in `extra` no
  longer erases a default. Helpers also accept `options` as a fourth argument.
- **Breaking: `sdk/shell/premier-emit.sh` exits non-zero when the collector
  rejects an event.** It used to print the error body and exit `0`.
- `premier record` always exits with the recorded command's own status. A
  stop signal received by the recorder is recorded separately and no longer
  stands in for it.
- A forwarded SIGTERM, SIGHUP, or SIGQUIT escalates to SIGKILL after the grace
  period, and a third rapid Ctrl-C kills a command that ignores interrupts.
- `premier recover` reads the recorder lease: it refuses a trace whose
  recorder is still running, and recovers one whose recorder is dead without
  waiting for the 300-second idle period.
- `premier open <trace>` and `premier record --open` serve only that trace,
  not every trace in the same directory.
- Redaction rules now apply to adapter events, to the raw stdout copy of an
  adapter run, and to the recorded command line. `premier export` and the
  recorder share one list of secret field names.
- `--redact-field` rejects a name with no letter or digit.
- The lifecycle validator matches what the SDK, the adapters, and the demo
  emit: a standalone `model.response` or `tool.result`, and an open
  `agent.spawn`, are no longer reported.
- An adapter event that states a failure in its native payload counts as an
  issue in the trace list and the viewer.
- The local assistant runs in an empty temporary directory instead of the
  trace directory, one request at a time, with Premier's server and collector
  secrets removed from its environment.
- `premier emit` and `premier-emit.sh` ignore proxy environment variables for
  a loopback collector.
- The npm launcher forwards SIGTERM and SIGHUP (and, without a terminal,
  SIGINT and SIGQUIT) to the native binary instead of leaving it running.
- `premier demo --output` replaces a directory only when it is recognisably a
  Premier trace, and never the current directory or one of its ancestors.

### Fixed

- `premier replay` no longer panics on a very small `--speed`.
- The viewer event stream of a finalized trace always ends with
  `trace.complete`, also when the trace cannot be read back at that moment.
- A recorder that loses the race for a trace directory fails before it
  writes anything, instead of overwriting the winner's manifest.
- Finalization, recovery, and `encrypt` sync the containing directory after
  each rename, and the durability of a trace is documented in
  [docs/trace-format.md](docs/trace-format.md#layout).

- A collector client that left a request half-sent could keep `premier
  record` from finalizing its trace.
- `premier replay` slept for the full length of any recorded gap, however
  long.
- `query`, `list`, and the other evidence commands failed with a broken-pipe
  error when piped into a command that exits early, such as `head`.
- A recorder that was suspended for more than 300 seconds was reported as
  abandoned and could be recovered underneath itself.
- The viewer's event stream for an abandoned trace never ended.
- Viewer: opening a very large trace waited for the whole journal before
  showing anything.
- A terminal Ctrl-C was delivered to the recorded command twice.
- Secrets split across output chunks, or straddling the read buffer, escaped
  `--redact-literal` and `--redact-regex`.
- `--pty` started the command in the home directory instead of the current
  one.
- Signal names in `process.exit` were wrong on platforms whose numbering
  differs from Linux.
- A journal write error (for example a full disk) ended the recording. The
  command now keeps running and keeps its exit status.
- Recording did not finish while a descendant of the command kept the output
  pipe open.
- A partial output line held back for a redaction rule, such as a prompt, was
  lost if the recorder was killed before the line ended. It is now stored
  after 1 second of quiet.
- Pending approvals in the viewer are settled by a later decision.
- Viewer: an empty screen that could not be left, a crash on very large
  traces, and adapter payloads that were not read.
- The release signer identity checked by the install and verification scripts
  matches the release workflow.

### Security

- The local assistant CLI no longer inherits `PREMIER_SIGN_KEY_FILE`.
- Documented a limit of encrypted traces: someone without the key who kept
  a copy of a manifest written during recording can roll a finalized trace
  back to what looks like an interrupted recording, which `premier recover`
  then finalizes, marked `seal.recovered`. See
  [docs/security.md](docs/security.md#encrypted-traces).

- An edit to a manifest field, or to the order or content of events, now
  fails `premier verify`. Detecting a deliberate rewrite still requires a
  signature checked against a key the verifier trusts.
- The collector rejects look-alike names (Unicode inside `kind`, `source`, or
  `actor_type`) and control characters in identity fields, and a producer can
  no longer back-date or forward-date an event.
- Recorded text can no longer send escape sequences to the terminal or forge
  output lines through the CLI's text output.
- Exports are created owner-only, and exporting an encrypted trace warns that
  the result is plaintext.
- The viewer API no longer reveals the server-side path of the trace
  directory.
- Codex is not offered as a local assistant when its command-execution
  features cannot be confirmed off.
- The viewer server refuses requests whose `Host` is not a loopback name when
  no credentials are configured (DNS rebinding), and refuses cross-origin
  requests to its API.
- The recorded process can no longer forge its own exit status, terminal
  output, or adapter events through the collector.
- Secret-named flags, assignments, and headers on the recorded command line
  are redacted in the manifest and in `session.start`.
- A recorded command that prints its environment no longer leaves the
  collector token in the trace.
- Credentials in header-style pairs, argument lists, and JSON strings inside
  event payloads, and in URL query strings, are redacted when recorded
  rather than only when exported.
- Assistant answers are sanitized before the viewer renders them as Markdown.
- The local assistant is confined and capped, and can be disabled.
- The collector token is not sent through an HTTP proxy for a loopback
  collector.
- `premier encrypt` refuses to re-seal a trace that fails verification.
