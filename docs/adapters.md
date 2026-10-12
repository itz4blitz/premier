# Native adapters

Some agent CLIs can print their activity as JSON, one object per line. When
the recorded command does that, a native adapter reads the lines from its
stdout and adds typed events (model calls, tool calls, approvals) to the
trace alongside the raw output.

That is all "native structured capture" means. Premier does not hook into the
agent, intercept its API traffic, or read its session files. It normalizes
what the CLI prints.

## When an adapter runs

An adapter runs only when all of these are true:

- The command is recorded without `--pty`.
- `--adapter` is not `none`.
- Either `--adapter <provider>` names a provider, or `--adapter auto` (the
  default) recognises the command.

`--adapter auto` looks at two things: the executable's file name (directories
and extension ignored, compared in lowercase) and the arguments.

| Provider | `--adapter` value | Executable name | Arguments that activate `auto` |
| --- | --- | --- | --- |
| Claude Code | `claude` | `claude` | `--output-format stream-json` or `--output-format=stream-json` |
| OpenAI Codex | `codex` | `codex` | `--json` |
| Gemini CLI | `gemini` | `gemini` | `--output-format stream-json` or `--output-format=stream-json` |
| Grok | `grok` | `grok` | `--output-format streaming-json` or `--output-format=streaming-json` |
| Kimi | `kimi` | `kimi` | `--output-format stream-json` or `--output-format=stream-json` |
| OpenCode | `opencode` | `opencode` | `--format json` or `--format=json` |
| Droid | `droid` | `droid` | `--output-format json`, `--output-format=json`, `-o json`, or `-o=json` |

```sh
premier record -- codex exec --json "review this repository"
premier record -- claude -p --output-format stream-json "fix the failing test"
```

`auto` matches only the first word of the recorded command. A wrapper hides
the agent from it:

```sh
# Not detected: the executable is `npx` / `sh`, not `claude`.
premier record -- npx claude -p --output-format stream-json "..."

# Name the adapter instead.
premier record --adapter claude -- npx claude -p --output-format stream-json "..."
```

An explicit `--adapter <provider>` is used as given. The executable name and
arguments are not checked, so the output must really be that provider's JSONL.

When an adapter is active the manifest records it:

```json
"adapter": {
  "provider": "claude",
  "schema_version": 1,
  "transport": "stdout-jsonl",
  "completeness": "provider-native-best-effort"
}
```

and gains the capability `adapter.<provider>.v1`.

## Limits

- **Interactive and `--pty` sessions get terminal capture only.** Adapters
  need pipe capture and line-delimited JSON. Run an agent in its interactive
  UI, or under `--pty`, and the trace holds its terminal output, the exit
  status, and whatever the harness emits through the
  [collector](collector.md), with no model, tool, or approval events from an
  adapter. Combining `--pty` with an explicit adapter is an error.
- **No structured-output flag, no adapter.** `premier record -- claude "..."`
  without the arguments in the table is recorded as plain terminal output.
- **Only stdout is parsed.** stderr is stored as terminal output.
- **Classification is heuristic.** One shared normalizer handles every
  provider. It decides what a line is from substrings of a few discriminator
  fields, not from a schema for each provider and version. A line with an
  unfamiliar shape can be given the wrong kind, or fall through to
  `provider.event`. The provider's original object is always kept in
  `payload.native`, so the evidence is there even when the label is wrong.
- **Completeness is best effort.** The adapter can only report what the CLI
  prints. The manifest says so: `completeness: "provider-native-best-effort"`.

## What is extracted

Each stdout line that parses as a JSON object becomes one event, plus one
event for each additional tool call or result packed into the same line.
Leading whitespace and terminal escape sequences in front of the object are
skipped. The raw stdout is still stored as `process.stdout`.

Every adapter event has:

- `source`: `adapter.<provider>.v1`
- `actor_id`: the provider id (`claude`, `codex`, ...), `actor_type`: `agent`,
  unless it belongs to a subagent (see below)
- a payload with these normalized fields:

| Payload field | Present when | Taken from |
| --- | --- | --- |
| `provider` | always | The adapter. |
| `adapter_schema_version` | always | `1`. |
| `native_type` | always | The first string among `type`, `event`, `kind`, `method`, `item.type`, `part.type`, lowercased; `unknown` if none. |
| `tool` | tool and approval events, when a name is found | The nested tool block's `name`, else `tool_name`, `toolName`, `tool`, `item.tool`, `item.name`, `part.tool`, `part.name`, `function.name`, `name`, `item.type`. A result with no name reuses the name from the invocation with the same id. |
| `command` | tool and approval events | `command` or `item.command`. |
| `model` | when stated | `model`, `message.model`, `item.model`, `response.model`, `part.model`, `modelID`, `part.modelID`. |
| `usage.input_tokens` | when stated | `input_tokens`, `prompt_tokens`, `inputTokens`, or `input` of the usage object. |
| `usage.output_tokens` | when stated | `output_tokens`, `completion_tokens`, `outputTokens`, or `output`. |
| `usage.total_tokens` | when stated or computable | `total_tokens`, `totalTokens`, or `total`; otherwise input plus output when both are known. |
| `usage.input_tokens_details.cached_tokens` | when stated | `cached_input_tokens`, `cache_read_input_tokens`, `cached_tokens`, `input_tokens_details.cached_tokens`, or `cache.read`. |
| `usage.output_tokens_details.reasoning_tokens` | when stated | `reasoning_output_tokens`, `reasoning_tokens`, `reasoning`, or `output_tokens_details.reasoning_tokens`. |
| `usage.cost_usd` | when stated | Top-level `total_cost_usd` or `cost_usd`, the usage object's `cost_usd`, or `part.cost`. |
| `parent_actor` | subagent events | The provider id. |
| `native` | always | The provider's JSON object for this line, or the nested block for a per-block event. |
| `native_truncated` | oversized lines | See [Oversized lines](#oversized-lines). |

The usage object is the first of `usage`, `message.usage`, `item.usage`,
`response.usage`, `part.usage`, `part.tokens`, `tokens`, `stats` that is an
object. Usage fields are copied, never estimated: a line with no usage has no
`usage`.

`duration_ms` on the event is taken from `duration_ms` or `item.duration_ms`
when present.

## How events are derived

### Kind

The adapter gathers the string values of the keys `type`, `subtype`, `kind`,
`event`, `hook_name`, and `role` anywhere in the line, skipping tool arguments
and output (`input`, `arguments`, `args`, `parameters`, `output`,
`aggregated_output`, `tool_input`, `tool_response`). It then picks the first
rule that matches:

| If the gathered values contain | Kind while running | Kind when completed |
| --- | --- | --- |
| `approval` or `permission` | `approval.request` | `approval.decision` |
| `tool`, `command_execution`, `function_call`, or `mcp_` | `tool.invocation` | `tool.result` |
| `assistant`, `message`, `model`, or `turn` | `model.request` | `model.response` (also whenever they contain `assistant` or `message`) |
| `session`, `thread`, `agent`, or `step` | `agent.turn` | `agent.result` |
| none of these | `provider.event` | `provider.event` |

Two provider-specific rules run first: a Droid line whose `type` is `result`
is a `model.response`, and a Kimi line whose `role` is `tool` is a
`tool.result`.

A line counts as completed when the gathered values contain `completed`,
`result`, `finish`, or `end`; or when the line, its `item` or `part`, or their
`state` has an exit code or a `status` / `state` of `completed`, `complete`,
`success`, `succeeded`, `done`, or `finished`; or when it carries an approval
decision.

### Failure

An event gets status `error` when the provider says so explicitly:

- `is_error` or `isError` is `true`;
- `status` or `state` is `error`, `errored`, `failed`, `failure`, `denied`, or
  `rejected`;
- `exit_code` or `exitCode` is a non-zero integer;
- `error` is present and not `null`, empty, `false`, or `0`;
- or the event's own type (`type`, `subtype`, `event`, `kind`, `method`,
  `item.type`, `part.type`, or the nested block's `type`) contains `error` or
  `fail`.

These are read from the line, its `item` or `part`, their `state`, and the
nested tool block the event stands for. The text of tool arguments, tool
output, and model prose is never searched, so a tool that prints the word
"error" does not fail. A failure also ends the lifecycle: a failing tool line
is a `tool.result` even if the provider never says "completed".

Otherwise the status is `pending` for an `approval.request`, `ok` for
completed events and for any `*.response` or `*.result`, and `running` for the
rest.

### Approvals

For lines classified as approvals the adapter looks for a decision: a boolean
`approved`, `allowed`, or `granted`, or a string `decision`, `status`,
`state`, `outcome`, or `behavior`. Approve-like values give status `approved`;
deny-like values (`denied`, `deny`, `rejected`, `reject`, `declined`,
`blocked`) give status `denied`. A grant and a refusal are kept distinct
rather than folded into `ok` and `error`.

### Tool pairing

A tool call and its result are paired by a shared `correlation_id`. For tool
and approval events it is the first id found among `call_id`, `tool_use_id`,
`tool_call_id`, `tool_id`, `callID`, `toolCallId`, `toolUseId` on the line,
then on its `part`, then its `item`, then the nested tool block (or that
block's `id`), then `item.id` or `id`.

- When one message carries several tool blocks (`message.content[]` or
  `content[]` entries whose `type` contains `tool`), each block becomes its
  own `tool.invocation` or `tool.result` with its own id.
- OpenAI-style `tool_calls` on an assistant message each become a
  `tool.invocation`.
- If the provider gives a call and its result no common id, they are not
  paired.

### Spans and subagents

- The session or thread id (`session_id`, `sessionID`, `sessionId`,
  `thread_id`, `threadId`, `part.sessionID`) is remembered and used as the
  root span.
- An event's `span_id` is its correlation id, or the session id if it has
  none. Its `parent_span_id` is the session id, or empty when its span is the
  session itself.
- **Subagents** are derived from one field: a string `parent_tool_use_id` on
  the line, which Claude Code sets on messages produced inside a tool call
  that spawned a subagent. Such an event gets `actor_id`
  `<provider>:subagent:<parent_tool_use_id>`, `actor_type` `subagent`,
  `parent_span_id` set to that tool id, and `payload.parent_actor`. Providers
  that do not print this field produce a single actor.

## Oversized lines

| Line size | Handling |
| --- | --- |
| Up to 256 KiB | Normalized and stored whole. |
| Over 256 KiB, up to 16 MiB | Normalized from the full line, so kind, status, and pairing are exact. The stored copy is shrunk: each string longer than 8 KiB keeps a prefix followed by `… [premier truncated: kept N of M bytes]`. If the payload is still over 256 KiB, strings are cut to 256 bytes instead. `payload.native_truncated` records `line_bytes`, `truncated_values`, and `omitted_bytes`. |
| Over 256 KiB and not valid JSON | One `adapter.diagnostic` with `line_bytes`. |
| Over 16 MiB | The line is not buffered. It is discarded and one `adapter.diagnostic` with `line_bytes` is written. |

A malformed line, or a JSON value that is not an object, also produces an
`adapter.diagnostic` (status `warning`) and nothing else. Adapter problems
never fail the recording or change its exit status.

The raw `process.stdout` copy is not affected by these limits.

## What is not derived

- **`parent_event_id` and `links`.** Adapters link events by span and
  correlation id only.
- **Timestamps.** An adapter event is stamped with the time the recorder read
  the line, not a time from the provider.
- **Prompt and response text as normalized fields.** They stay inside
  `payload.native` in the provider's own shape.
- **Token usage or cost the provider did not print.** Nothing is estimated
  from text or from a price table.
- **Tool duration**, unless the line has `duration_ms`.
- **Subagents, approvals, or model requests the CLI does not print.** If the
  CLI's JSON output has no line for something, there is no event for it.
- **Anything from stderr or from an interactive UI.**

To add what an adapter cannot see, emit it from the harness with the
[SDK](../sdk/js/README.md) or the [collector](collector.md). Collector events
and adapter events share one journal.

## Redaction

Both the normalized events and the raw stdout copy are redacted; see
[redaction.md](redaction.md#adapter-runs).
