# Changelog

Changes a user of the `premier` CLI, the viewer, or `@premierstudio/trace`
would notice. Entries marked **Breaking** change behaviour that scripts or
integrations may depend on.

## Unreleased

### Added

- **Built-in secret value patterns.** Values shaped like well-known
  credentials (API keys, bearer credentials, URL passwords, private key
  blocks, JWTs, GitHub, AWS, and Slack tokens) are redacted from structured
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

- The viewer server refuses requests whose `Host` is not a loopback name when
  no credentials are configured (DNS rebinding), and refuses cross-origin
  requests to its API.
- The recorded process can no longer forge its own exit status, terminal
  output, or adapter events through the collector.
- Secret-named flags, assignments, and headers on the recorded command line
  are redacted in the manifest and in `session.start`.
- Assistant answers are sanitized before the viewer renders them as Markdown.
- The local assistant is confined and capped, and can be disabled.
- The collector token is not sent through an HTTP proxy for a loopback
  collector.
- `premier encrypt` refuses to re-seal a trace that fails verification.
