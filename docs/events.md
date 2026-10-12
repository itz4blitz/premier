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
| `timestamp` | producer or recorder | RFC 3339. The producer's value if it sent one, otherwise the time the recorder received the event. |
| `kind` | producer | What happened, for example `tool.result`. |
| `source` | producer | Which producer wrote it. |
| `actor_id`, `actor_type` | producer | Who did it. |
| `status` | producer | Outcome or state. |
| `duration_ms` | producer | How long it took, when known. |
| `parent_event_id`, `span_id`, `parent_span_id`, `correlation_id`, `links` | producer | [Causality](#causality-fields). |
| `payload_json` | producer | The payload, stored as a JSON string. |

## Kinds the recorder writes

Only the recorder can write these. Their `actor_id` is `root` and their
`actor_type` is `process`.

| Kind | Source | Status | When | Payload |
| --- | --- | --- | --- | --- |
| `session.start` | `premier` | `running` | First event of every recording. Span `session`. | `cwd`, `command`, `instrumentation` (collector URL), `capture_mode` (`pipes` or `pty`), `adapter` (provider, schema version, transport, completeness, or `null`), and `terminal` (rows, cols, pixel size) under `--pty` |
| `process.stdout`, `process.stderr` | `command` | `running` | Captured output without `--pty`. Span `command`, parent span `session`. | `text`, `byte_length`, `stream` |
| `process.terminal` | `command` | `running` | Captured output with `--pty` (stdout and stderr merged). | `text`, `byte_length`, `stream: "pty"` |
| `process.exit` | `command` | `ok` if the exit code is 0, otherwise `error` | The command ended. | `exit_code`, `success`, `termination` (`exit` or `signal`), and when applicable `signal`, `signal_name`, `forwarded_by_recorder`, `recorder_signal`, `recorder_signal_name`, `killed_by_recorder`, `core_dumped`, `output_open_at_exit` |
| `process.spawn_failed` | `premier` | `error` | The command could not be started. Replaces `process.exit`. | `executable`, `error`, `exit_code` (127 or 126), `success: false` |
| `session.interrupted` | `premier-recovery` | `error` | Appended by `premier recover` to an abandoned trace. | `reason`, `recovered_event_count`, `discarded_trailing_bytes` |

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
| `agent.turn` / `agent.result` | A session, thread, agent, or step event; `agent.result` when the provider marks it complete. |
| `model.request` / `model.response` | A model or turn event; `model.response` for assistant messages and completed turns. |
| `tool.invocation` / `tool.result` | A tool call and its outcome. |
| `approval.request` / `approval.decision` | A permission or approval event and its outcome. |
| `provider.event` | A provider line that fits none of the above. |
| `adapter.diagnostic` | A line the adapter could not use (malformed, not an object, or too large). Status `warning`. Payload: `provider`, `adapter_schema_version`, `line`, `message`, and `line_bytes` for oversized lines. |

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
`process.`, and as an agent otherwise. An empty `actor_id` is shown as `root`.

## Causality fields

All five are optional strings (or, for `links`, a list of strings) chosen by
the producer. Premier does not generate them, apart from the recorder's own
`session` and `command` spans and the ids adapters take from the provider.

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
  `parent_event_id` empty. `premier emit --span/--parent-span` and the native
  adapters work this way.
- The viewer's search box matches `event_id`, `span_id`, `parent_span_id`, and
  `correlation_id` as well as kind, source, actor, status, and payload text.
- `premier diff` ignores all of these fields.

## Lifecycle validation

When a trace is finalized, Premier validates its events and stores the
findings as `diagnostics` in the manifest. `premier verify` prints them, and
the viewer lists them under missing evidence. Every diagnostic has severity
`warning`, a `code`, a `message`, and usually the `event_id` and `sequence` it
refers to.

Diagnostics describe gaps in what producers recorded. They never make a trace
fail verification.

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
| `invalid_status` | `status` is not one of the statuses listed above (compared case-insensitively). |
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
`agent.message` are single events with no pair.

A finish is matched to a start like this:

1. If the finish has a `correlation_id`: the first start with the same
   `correlation_id`. Nothing else is tried.
2. Otherwise: the first start with the same `span_id`; failing that, the first
   start whose `span_id` is the finish's `parent_span_id`; failing that, the
   first start with the same `actor_id`.

| Code | Raised when |
| --- | --- |
| `missing_lifecycle_start` | A finish matches no start, in a lifecycle where that is flagged. |
| `missing_lifecycle_finish` | A start is matched by no finish, in a lifecycle where that is flagged. A start that shares its `correlation_id` with a matched start is not flagged, so a hook and the call it wraps count as one. |
| `missing_causal_link` | A finish matches a start but nothing links the two. A link is any of: the finish's `parent_event_id` is the start; its `links` contain the start; both have the same non-empty `span_id`; the finish's `parent_span_id` is the start's `span_id` or `parent_span_id`; both have the same non-empty `correlation_id`. |

In practice: give each request/decision, delegation/join, and
invocation/result pair its own `correlation_id` or `span_id`. Two open
requests from the same actor with neither are both matched to the first one,
and the second is reported as unfinished.

### Recorder diagnostics

| Code | Raised when |
| --- | --- |
| `journal.write_failed` | The recorder could not write one or more events to the journal. The message gives the count. See [cli.md](cli.md#journal-write-failure). |

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
- `adapter.diagnostic` has status `warning` and is not an issue.
- Manifest diagnostics are not issues. They are reported separately as
  missing evidence.
- `premier query --status error` filters on the exact status only. It is not
  the issue predicate.
