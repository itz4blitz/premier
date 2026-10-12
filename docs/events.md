# Events

A trace is an ordered journal of events. This page lists the event kinds
Premier's own producers write, the fields that link events together, and the
checks Premier runs over them.

Kinds are free-form strings. Premier stores any kind it is given, apart from
the ones reserved for the recorder (see
[collector.md](collector.md#reserved-kinds-and-sources)). The lists below are
the vocabulary the viewer and the validator understand.

## Event fields

| Field | Set by | Meaning |
| --- | --- | --- |
| `event_id` | recorder | Unique id of this event. |
| `trace_id` | recorder | The trace it belongs to. |
| `sequence` | recorder | Position in the journal, starting at 1 with no gaps. |
| `timestamp` | recorder | RFC 3339. Always the time the recorder wrote the event: the receipt time for collector events, the time the line was read for adapter events. A producer's own time is kept in the payload instead, as `producer_timestamp` (collector) or `native_timestamp` (adapters). |
| `kind` | producer | What happened, for example `tool.result`. |
| `source` | producer | Which producer wrote it. |
| `actor_id`, `actor_type` | producer | Who did it. |
| `status` | producer | Outcome or state. |
| `duration_ms` | producer | How long it took, when known. |
| `parent_event_id`, `span_id`, `parent_span_id`, `correlation_id`, `links` | producer | [Causality](#causality-fields). |
| `payload_json` | producer | The payload, stored as a JSON string. |
| `prev_hash` | recorder | Format version 2: the hash of the previous event, which chains the journal. See [trace-format.md](trace-format.md#event-hash-chain). |

Events that arrive through the collector are validated field by field
(allowed characters and lengths); see
[collector.md](collector.md#field-rules).

## Kinds the recorder writes

Only the recorder can write these. Their `actor_id` is `root` and their
`actor_type` is `process`.

| Kind | Source | Status | When | Payload |
| --- | --- | --- | --- | --- |
| `session.start` | `premier` | `running` | First event of every recording. Span `session`. | `cwd`, `command`, `instrumentation` (collector URL), `capture_mode` (`pipes` or `pty`), `adapter` (provider, schema version, transport, completeness, or `null`), and `terminal` (rows, cols, pixel size) under `--pty` |
| `process.stdout`, `process.stderr` | `command` | `running` | Captured output without `--pty`. Span `command`, parent span `session`. | `text`, `byte_length`, `stream`, and `lossy`, `replaced_sequences` when the output was not valid UTF-8 (see below) |
| `process.terminal` | `command` | `running` | Captured output with `--pty` (stdout and stderr merged). | `text`, `byte_length`, `stream: "pty"`, and `lossy`, `replaced_sequences` as above |
| `process.resize` | `premier` | `running` | With `--pty`: the recorder's terminal was resized and the PTY was resized to match. | `rows`, `cols`, `pixel_width`, `pixel_height` |
| `process.exit` | `command` | `ok` if the exit code is 0, otherwise `error` | The command ended. | `exit_code`, `success`, `termination` (`exit` or `signal`), and when applicable `signal`, `signal_name`, `forwarded_by_recorder`, `recorder_signal`, `recorder_signal_name`, `killed_by_recorder`, `core_dumped`, `output_open_at_exit` |
| `process.spawn_failed` | `premier` | `error` | The command could not be started. Replaces `process.exit`. | `executable`, `error`, `exit_code` (127 or 126), `success: false` |
| `session.interrupted` | `premier-recovery` | `error` | Appended by `premier recover` to an abandoned trace. Its timestamp is the time of the recovery. | `reason`, `recovered_event_count`, `discarded_trailing_bytes`, `exit_recorded` (whether the kept events hold the command's `process.exit`), `last_activity_at` (when the abandoned recording was last written to), and `discarded_frames`, `discard_reason` when something was discarded |
| `collector.unauthorized` | `premier` | `denied` | The first request of a recording that reached the collector without its token. Later ones are not recorded. Span `session`. | `reason`, `note` |

**Captured output is text, not bytes.** `text` is the output decoded as UTF-8.
Each invalid sequence is replaced with U+FFFD, and the original bytes are not
kept anywhere in the trace (the output mirrored to the recorder's own stdout
and stderr is exact). An event whose text contains such a replacement has
`lossy: true` and `replaced_sequences`, the number of sequences replaced
since the last marked event of that stream, so a replacement can be told from
a U+FFFD the command really printed. When a redaction rule holds text back,
the mark is on the first event stored after the replacement that contains a
U+FFFD. `byte_length` counts the bytes read from the command for the event,
before decoding and before redaction, so it can differ from the length of
`text`.

The `process.exit` fields are explained in [cli.md](cli.md#exit-status).

## Kinds the SDK helpers write

The JavaScript helpers in [`@premierstudio/trace`](../sdk/js/README.md) write
these with source `premier-sdk`.

| Helper | Kind | Default `actor_type` | Default `status` |
| --- | --- | --- | --- |
| `premier.delegation` | `agent.delegation` | `agent` | `running` |
| `premier.spawn` | `agent.spawn` | `subagent` | `running` |
| `premier.result` | `agent.result` | `subagent` | `ok` |
| `premier.join` | `agent.join` | `agent` | `ok` |
| `premier.message` | `agent.message` | `agent` | `ok` |
| `premier.model` | `model.response` | `agent` | `ok` |
| `premier.tool` | `tool.execution` | `agent` | `ok` |
| `premier.approval` | `approval.request` | `agent` | `pending` |
| `premier.approvalDecision` | `approval.decision` | `human` | `approved` |

`emit`, `premier emit`, and a direct POST can send any kind. `premier emit`
uses source `premier-emit` by default, and a POST with no `source` is stored
with source `sdk`.

`premier demo` writes `session.start`, `agent.delegation`, `agent.spawn`,
`model.response`, `tool.execution`, `tool.error`, `agent.message`,
`approval.request`, `approval.decision`, and `agent.join` with source
`premier-demo`.

## Kinds the adapters write

Native adapters (see [adapters.md](adapters.md)) write these with source
`adapter.<provider>.v1`.

| Kind | Meaning |
| --- | --- |
| `agent.turn` | The start of a session (`payload.lifecycle: "session_start"`) or of a turn (`"turn_start"`), and any other session, thread, agent, step, or turn line that is not complete. |
| `agent.result` | The final result of a run or turn (`payload.lifecycle: "run_result"`), with `payload.usage` and cost when the provider prints them, and any other session, thread, agent, step, or turn line the provider marks complete. |
| `agent.spawn` / `agent.result` with `payload.synthesized: true` | The start and end of a subagent. No provider line states them; the adapter infers them and marks them. See [adapters.md](adapters.md#spans-and-subagents). |
| `model.request` / `model.response` | A model event; `model.response` for assistant and message lines, OpenCode `text` parts, Codex `reasoning` items (`payload.reasoning: true`), completed model events, and an assistant message that has both text and tool calls (its tool calls follow as events of their own). `payload.usage` is attached to the first event of a provider message; later events of that message carry `payload.usage_reported_on` instead. |
| `agent.message` | A line spoken by the user rather than the model (`role`, or `message.role`, is `user`), with status `ok` and `payload.role: "user"`. A user line that carries tool results is a `tool.result` instead. |
| `tool.invocation` / `tool.result` | A tool call and its outcome, including Codex `file_change` and `web_search` items. A result the provider marks `denied`, `rejected`, `declined`, or `blocked` has status `denied`; other failures have status `error`. |
| `approval.request` / `approval.decision` | A permission or approval event and its outcome. |
| `approval.decision` with `payload.synthesized: true` | One per entry of Claude Code's `permission_denials`, status `denied`. No `approval.request` precedes it; because it is marked as inferred, the validator does not report that as `missing_lifecycle_start`. See [adapters.md](adapters.md#approvals). |
| `provider.event` | A provider line that fits none of the above. |
| `adapter.diagnostic` | A line the adapter could not use (malformed, not an object, or too large). Status `warning`. Payload: `provider`, `adapter_schema_version`, `line`, `message`, and `line_bytes` for oversized lines. At most 20 per recording; the twentieth carries `further_diagnostics: "suppressed"`. |
| `adapter.summary` | Written once at the end of an adapter recording in which some or all output lines were not native events. Status `warning`. Payload: `provider`, `adapter_schema_version`, `lines`, `normalized_lines`, `rejected_lines`, `suppressed_diagnostics`, `completeness`, `message`. See [adapters.md](adapters.md#when-an-adapter-runs). |

## Statuses

The validator accepts these statuses on the kinds it checks:

```text
running  ok  error  failed  denied  blocked  pending  approved
rejected  cancelled  completed  success  warning  skipped
```

Any string is stored. The ones with behaviour attached:

| Status | Effect |
| --- | --- |
| `error`, `failed`, `denied`, `blocked` | The event is an [issue](#what-counts-as-an-issue). |
| `pending` | The viewer treats the event as awaiting a decision until a later `approval.decision`, or any later event with status `approved` or `denied`, shares its `correlation_id` or `span_id`. |
| `approved`, `denied` | Settle a pending event as above. |
| `running` | The actor is shown as active. |

`rejected` is valid but is not an issue status. Use `denied` for a refused
approval if it should be counted and surfaced as a failure.

## Actor types

| `actor_type` | Meaning |
| --- | --- |
| `process` | The recorded OS process. Used by the recorder for `root`. |
| `agent` | A top-level agent. |
| `subagent` | An agent started by another agent. |
| `human` | A person, for example the approver of an `approval.decision`. |
| `system` | Infrastructure that is neither an agent nor a person. |

When `actor_type` is empty or anything else, the viewer treats the actor as a
process if its `actor_id` is empty or `root`, or the kind starts with
`process.`, and as an agent otherwise. The viewer groups an empty `actor_id`
under `root`. `premier query` prints it as `-`, because an event without an
actor is unattributed, not the root process.

## Causality fields

All five are optional strings (or, for `links`, a list of strings) chosen by
the producer. Premier does not generate them, apart from the recorder's own
`session` and `command` spans and what the native adapters derive: spans and
correlation ids taken from the provider, and `parent_event_id` and `links`
resolved to the ids of events the adapter stored earlier (see
[adapters.md](adapters.md#parents-and-links)).

| Field | Meaning | How the viewer uses it |
| --- | --- | --- |
| `parent_event_id` | The `event_id` of the event that directly caused this one. | The inspector's parent and children. Timeline nesting depth. The ancestors and effects of a failure in the investigation chain. Connections between actors in the topology and architecture views. |
| `span_id` | Names a unit of work. Several events can share one span; the earliest is the span's opener. | Resolves `parent_span_id` references. Settles pending approvals. Pairs lifecycle events in the validator. |
| `parent_span_id` | The span this event's work belongs under. | Used as the parent when `parent_event_id` is absent or does not resolve: the parent is the opener of that span. For actor connections it is used only when every event in that span has the same actor; otherwise the reference is reported as ambiguous instead of guessed. |
| `correlation_id` | Ties together several records of one logical operation: a tool call and its result, a request and its decision. | The inspector lists the other events with the same id, and can filter the timeline to them. Settles pending approvals. Pulls nearby correlated events into the investigation chain. First choice for pairing lifecycle events in the validator. |
| `links` | Other events this one refers to, by event id or span id, without a parent/child meaning. | The inspector shows outgoing links and the events that link to this one, and marks a link whose target is not in the trace. Links never create connections between actors. |

Notes:

- A `parent_event_id` must name an event that was recorded earlier. A
  reference to a later or unknown event is reported as `unknown_parent_event`.
- If you only track spans, set `span_id` and `parent_span_id` and leave
  `parent_event_id` empty. `premier emit --span/--parent-span` works this
  way; `--parent-event`, `--correlation`, and `--link` set the other
  causality fields. The native adapters set spans and, where an earlier stored event is
  the cause, `parent_event_id` as well.
- The viewer's search box matches `event_id`, `span_id`, `parent_span_id`, and
  `correlation_id` as well as kind, source, actor, status, and payload text.
- `premier diff` ignores all of these fields.

## Lifecycle validation

When a trace is finalized, Premier validates its events and stores the
findings as `diagnostics` in the manifest. `premier verify` and the viewer
server do not report that stored list as it is: they run the validator of the
build that is reading the trace over its events, and take from the manifest
only the [recorder diagnostics](#recorder-diagnostics), which cannot be
derived from the events. An older trace is therefore judged by the current
rules. `premier verify` prints the result, and the viewer lists it under
missing evidence. Every diagnostic has severity
`warning`, a `code`, a `message`, and usually the `event_id` and `sequence` it
refers to.

Diagnostics describe gaps in what producers recorded. They never make a trace
fail verification. They are part of the manifest, so in a format version 2
trace they are covered by the manifest seal.

### What is checked

**Parent references**, on every event:

| Code | Raised when |
| --- | --- |
| `unknown_parent_event` | `parent_event_id` is set and is not the id of an earlier event. |

**Shape**, on these 14 kinds only: `agent.spawn`, `agent.turn`,
`agent.result`, `agent.delegation`, `agent.join`, `agent.message`,
`model.request`, `model.response`, `tool.invocation`, `tool.result`,
`tool.execution`, `tool.error`, `approval.request`, `approval.decision`.

| Code | Raised when |
| --- | --- |
| `missing_status` | `status` is empty. |
| `invalid_status` | `status` is not one of the statuses listed above (compared case-insensitively, ignoring surrounding whitespace). |
| `payload_not_object` | The payload is not a JSON object. An omitted payload is `null` and raises this. |

**Lifecycles**, pairing a start with its finish:

| Start | Finish | Finish with no start | Start with no finish |
| --- | --- | --- | --- |
| `agent.spawn` or `agent.turn` | `agent.result` | flagged | allowed |
| `model.request` | `model.response` | allowed | flagged |
| `tool.invocation` | `tool.result` | allowed | flagged |
| `approval.request` | `approval.decision` | flagged | flagged |
| `agent.delegation` | `agent.join` | flagged | flagged |

`model.response` and `tool.result` may stand alone because producers also
record them as self-contained calls, and an agent's `spawn` or `turn` may stay
open or be closed by an `agent.join`. `tool.execution`, `tool.error`, and
`agent.message` are single events with no pair. `agent.message` is used both
for a message between agents (the SDK's `premier.message`) and, by the native
adapters, for a provider line spoken by the user (`payload.role: "user"`).

A finish is matched to a start recorded before it. A start that comes later
in the journal is never its match.

1. If the finish's `parent_event_id`, or one of its `links`, is the id of a
   start: that start.
2. Otherwise, if the finish has a `correlation_id`: a start with the same
   `correlation_id`. Nothing else is tried.
3. Otherwise: a start with the same `span_id`; failing that, a start whose
   `span_id` is the finish's `parent_span_id`; failing that, a start with the
   same `actor_id`.

Where rule 2 or 3 finds several starts, the finish closes the most recent one
that no finish has closed yet. When all of them are closed it counts as a
further record of the most recent one.

A finish with `payload.synthesized: true` (one an adapter inferred, such as a
denial taken from a summary) is not reported as `missing_lifecycle_start`:
there is no start it could name.

| Code | Raised when |
| --- | --- |
| `missing_lifecycle_start` | A finish matches no start, in a lifecycle where that is flagged. |
| `missing_lifecycle_finish` | A start is matched by no finish, in a lifecycle where that is flagged. A start that shares its `correlation_id` with a matched start is not flagged, so a hook and the call it wraps count as one. |
| `missing_causal_link` | A finish matches a start but nothing links the two. A link is any of: the finish's `parent_event_id` is the start; its `links` contain the start; both have the same non-empty `span_id`; the finish's `parent_span_id` is the start's `span_id` or `parent_span_id`; both have the same non-empty `correlation_id`. |

In practice: set `parent_event_id` on the finish, or give each
request/decision, delegation/join, and invocation/result pair its own
`correlation_id` or `span_id`. Pairs that only share an actor are closed in
order, most recent first, which is right for calls made one after another and
for nested ones, but can cross the pairs of calls that overlap; they also get
a `missing_causal_link` diagnostic each.

### Recorder diagnostics

| Code | Raised when |
| --- | --- |
| `journal.write_failed` | The recorder could not write one or more events to the journal. The message gives the count. See [cli.md](cli.md#journal-write-failure). |
| `journal.recovery_discarded` | `premier recover` could not keep part of the abandoned journal. The message gives the bytes, the frames when known, the sequence after which the cut was made, and the reason. See [cli.md](cli.md#damaged-journals). |

`adapter.diagnostic` is different: it is an event in the journal, written by a
native adapter about one provider line, not a manifest diagnostic.

## What counts as an issue

The viewer's issue filter and counts, and the issue count in the trace list,
use one predicate. An event is an issue when any of these holds:

1. Its `status` is `error`, `failed`, `denied`, or `blocked`
   (case-insensitive).
2. Its `kind` contains `error` or `fail`, for example `tool.error` or
   `process.spawn_failed`.
3. It is an adapter event whose provider object (`payload.native`) states a
   failure outright: `is_error` / `isError` is `true`; `status` or `state` is
   `error`, `errored`, `failed`, `failure`, `denied`, or `rejected`;
   `exit_code` / `exitCode` is non-zero; `error` is present and non-empty; or
   its `type` is `error`. The status, exit code, and error fields are read
   from the provider object, its `item` or `part`, and their `state`. For an
   event that stands for one content block of a message, the block's own
   `is_error` flag is used. Tool arguments, tool output, and prose are never
   consulted.

Consequences worth knowing:

- A non-zero exit makes `process.exit` an issue, and so does a recovered
  `session.interrupted`.
- `adapter.diagnostic` has status `warning` and is not an issue. The viewer
  reports it as missing evidence instead: a run with `adapter.diagnostic` or
  `adapter.summary` events lists "Provider output was not fully captured",
  with the number of lines that were not read.
- Manifest diagnostics are not issues. They are reported separately as
  missing evidence.
- `premier query --status error` filters on the exact status only. It is not
  the issue predicate; `premier query --issues` is.
- `adapter.summary` has status `warning` and is not an issue either.
