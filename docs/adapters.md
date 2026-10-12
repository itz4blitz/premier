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
and extension ignored, compared in lowercase) and the arguments before any
`--`.

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

Arguments after `--` are positional, so they never activate an adapter:
`codex exec -- --json` runs Codex with the prompt `--json`, and is recorded
as plain terminal output.

`auto` looks through these wrappers to find the real executable, up to four
deep:

| Wrapper | What is skipped |
| --- | --- |
| `env` | `NAME=VALUE` assignments and the flags `-i`, `-`, `--ignore-environment`, `-u NAME`, `--unset[=]NAME`, `-C DIR`, `--chdir[=]DIR`, `--`. Any other flag, such as `-S`, leaves the command unresolved. |
| `npx`, `bunx`, `pnpx`, `pnpm dlx`, `yarn dlx` | The runner's own flags (`-p` / `--package` with its value; `-c` / `--call` leaves the command unresolved). The package is mapped to a provider with any `@version` removed: `@anthropic-ai/claude-code` is `claude`, `@openai/codex` is `codex`, `@google/gemini-cli` is `gemini`, `opencode-ai` is `opencode`, and a package named like a provider is that provider. |
| `sh`, `bash`, `zsh`, `dash`, `ksh` with `-c SCRIPT` (or a flag cluster such as `-lc`) | Nothing but single-dash flags may come before the script, and the script must be one simple command: no `|`, `;`, `&`, redirection, grouping, `#`, line break, backquote, or `$(...)`. Quotes and backslashes are read as the shell reads them, leading `NAME=VALUE` words and `exec` are dropped, and a `$VAR` argument is kept as an opaque word. |

```sh
premier record -- env CI=1 claude -p --output-format stream-json "..."
premier record -- npx -y @anthropic-ai/claude-code -p --output-format stream-json "..."
premier record -- sh -c 'claude -p --output-format stream-json "fix the test"'
```

Anything else hides the agent. Name the adapter instead:

```sh
# Not detected: a pipeline is not one simple command.
premier record -- sh -c 'claude -p --output-format stream-json "..." | tee out.jsonl'

premier record --adapter claude -- ./run-agent.sh
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
  adapter. Combining `--pty` with an explicit adapter is an error. When
  `--adapter auto` would have activated an adapter but `--pty` is given, the
  recorder prints one line to stderr and records terminal output only:

  ```text
  premier: structured capture for codex is unavailable in PTY mode; recording terminal output only (omit --pty for model and tool events)
  ```
- **No structured-output flag, no adapter.** `premier record -- claude "..."`
  without the arguments in the table is recorded as plain terminal output.
- **Only stdout is parsed.** stderr is stored as terminal output.
- **Classification is heuristic.** One shared normalizer handles every
  provider. It decides what a line is from a handful of exact line types and
  from whole words in a few discriminator fields, not from a schema for each
  provider and version. A line with an unfamiliar shape can be given the wrong
  kind, or fall through to `provider.event`. The provider's original object
  is always kept in `payload.native`, so the evidence is there even when the
  label is wrong.
- **The fixtures are hand-written.** The adapter tests run against files in
  `crates/premier-cli/tests/fixtures/adapters/`. Their
  [README](../crates/premier-cli/tests/fixtures/adapters/README.md) states
  that they were composed from knowledge of each CLI's stream format and were
  not captured from real runs, that a real stream may carry fields they omit
  or shape them differently, and that the Grok fixture is the least certain.
  They are regression inputs for the normalizer, not a specification of any
  provider's output.
- **Completeness is best effort.** The adapter can only report what the CLI
  prints. The manifest says so: `completeness: "provider-native-best-effort"`.

## What is extracted

Each stdout line that parses as a JSON object becomes one event, plus one
event for each additional tool call or result packed into the same line and
one for each entry of a result line's `permission_denials`.
Leading whitespace and terminal escape sequences in front of the object are
skipped. The raw stdout is still stored as `process.stdout`.

Two more events per subagent are not taken from any line: the adapter
synthesizes an `agent.spawn` and an `agent.result`. They, and the
`approval.decision` events drawn from `permission_denials`, are marked
`payload.synthesized: true`. See [Spans and subagents](#spans-and-subagents)
and [Approvals](#approvals).

Every adapter event that stands for a provider line has:

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
| `usage.total_tokens` | when stated or computable | `total_tokens`, `totalTokens`, or `total`; otherwise computed, see [Usage](#usage). |
| `usage.input_tokens_details.cached_tokens` | when stated | `cached_input_tokens`, `cache_read_input_tokens`, `cached_tokens`, `input_tokens_details.cached_tokens`, or `cache.read`. |
| `usage.input_tokens_details.cache_creation_tokens` | when stated | `cache_creation_input_tokens`, `cache_creation_tokens`, `cache_write_tokens`, `input_tokens_details.cache_creation_tokens`, or `cache.write`. |
| `usage.output_tokens_details.reasoning_tokens` | when stated | `reasoning_output_tokens`, `reasoning_tokens`, `reasoning`, or `output_tokens_details.reasoning_tokens`. |
| `usage.cost_usd` | when stated | Top-level `total_cost_usd` or `cost_usd`, the usage object's `cost_usd`, or `part.cost`. |
| `usage_reported_on` | later events of a message whose usage is already attached | The provider's message id. See [Usage](#usage). |
| `role` | `agent.message` events | `user`. See [Kind](#kind). |
| `paths` | Codex `file_change` items | The `path` of each entry in `item.changes`. |
| `query` | Codex `web_search` items, when stated | `item.query`. |
| `reasoning` | Codex `reasoning` items | `true`. |
| `synthesized`, `synthesized_from` | events no native line states by itself | See [Spans and subagents](#spans-and-subagents) and [Approvals](#approvals). |
| `parent_actor` | subagent events | The provider id. On a synthesized `agent.spawn`, the `actor_id` of its parent event, normally the tool call that spawned the subagent. |
| `lifecycle` | session start, turn start, and final result lines | `session_start`, `turn_start`, or `run_result`. See [Kind](#kind). |
| `session_id` | `agent.turn` and `agent.result` events of the main agent, once a session id is known | The session or thread id. |
| `native_timestamp` | when the line carries a recognisable time | The provider's own time for the line. See [Timestamps](#timestamps). |
| `native` | always | The provider's JSON object for this line, or the nested block for a per-block event. |
| `native_truncated` | oversized lines | See [Oversized lines](#oversized-lines). |

### Usage

The usage object is the first of `usage`, `message.usage`, `item.usage`,
`response.usage`, `part.usage`, `part.tokens`, `tokens`, `stats` that is an
object. Usage fields are copied from it, and the total is at most summed from
them; nothing is estimated, and a line with no usage has no `usage`.

`input_tokens` and `output_tokens` are the provider's own numbers. Providers
disagree on whether cached tokens are part of `input_tokens`, so
`total_tokens` is defined the same way for all of them: **every token the
call processed**.

- A total the provider states is used as stated.
- Otherwise, when both `input_tokens` and `output_tokens` are stated, it is
  their sum plus the cache tokens the provider counts *apart from* input:
  `cache_read_input_tokens` and `cache_creation_input_tokens` (Claude), and
  `cache.read` and `cache.write` (OpenCode).
- `cached_input_tokens`, `cached_tokens`, and
  `input_tokens_details.cached_tokens` (Codex and other OpenAI-style usage)
  are already inside `input_tokens` and are not added again.
- Reasoning tokens are never added; they are reported in
  `output_tokens_details.reasoning_tokens` only.

A Claude message with 10 input, 5 output, 3 cache-read, and 2 cache-creation
tokens therefore has `total_tokens: 20`; a Codex turn with 7 input (2 of them
cached) and 1 output has `total_tokens: 8`.

**One message, one usage.** Claude prints one line per content block and
repeats the whole message's usage on each. When the usage is stated on the
line's `message` (and not on the line itself), the adapter attaches `usage`
to the first event of a message id (`message.id`) only. Later events from the
same message carry `usage_reported_on: "<message id>"` instead, so summing
`payload.usage` over a trace's events counts each message once. The
provider's repeated copy stays in `payload.native`. If a later line of the
same message states different numbers, the first line's are the ones kept in
`usage`. The adapter remembers 1,024 message ids at a time.

A final result line (`lifecycle: "run_result"`) carries the provider's
cumulative usage for the run, so the run's totals appear on that
`agent.result` event. It repeats the per-message numbers; do not add it to
them.

`duration_ms` on the event is taken from `duration_ms`, `item.duration_ms`, or
`stats.duration_ms` when present.

### Timestamps

The `timestamp` of an adapter event is the time the recorder read the line.
It is never taken from the provider.

When the line states its own time, that value is kept beside the event as
`payload.native_timestamp`:

- It is the first usable value among the keys `timestamp`, `time`,
  `created_at`, `createdAt`, `created`, and `ts`, looked up on the line, then
  on its `message`, `item`, and `part`.
- An RFC 3339 string, or a number (or numeric string) of epoch seconds or
  epoch milliseconds, is accepted. An epoch value outside 2000-01-01 to
  roughly the year 5138 is taken to be a duration or a counter and ignored.
- It is normalized to RFC 3339 in UTC with millisecond precision, for example
  `2026-03-04T10:15:01.402Z`.
- Per-block events from one line share the line's value.

## How events are derived

### Kind

Rules are tried in this order, and the first that matches decides the kind.

**1. Session and turn boundaries, by exact line type.** The line's top-level
`type`, lowercased, is compared exactly:

| Line `type` | Kind | `payload.lifecycle` |
| --- | --- | --- |
| `system` with `subtype` `init`; `init`; `thread.started`; `session.started`; `session.start` | `agent.turn` | `session_start` |
| `turn.started` | `agent.turn` | `turn_start` |
| `result` (every provider except Droid); `turn.completed`; `turn.failed` | `agent.result` | `run_result` |

These are, for example, Claude Code's `system`/`init` and `result` lines,
Codex's `thread.started` and `turn.*` lines, and Gemini's `init` and `result`
lines.

**2. Provider-specific rules.**

| Provider | Line | Kind |
| --- | --- | --- |
| Droid | `type` is `result` | `model.response`. Droid's JSON mode prints one result object and nothing before it, so that object is the model's answer. |
| Kimi | `role` is `tool` | `tool.result` |
| OpenCode | `type` is `text` | `model.response`. OpenCode streams assistant prose as bare `text` parts. |
| Codex | `item.type` is `file_change` or `web_search` | A tool event: `tool.invocation` on `item.started`, `tool.result` once completed, with `payload.tool` set to the item type (unless the item names a tool) and `payload.paths` or `payload.query`. |
| Codex | `item.type` is `reasoning` | `model.response` with `payload.reasoning: true`, so it can be told from an answer. |
| Codex | `item.type` is `todo_list` | `provider.event` |

**3. Word rules.** The adapter gathers the string values of the keys `type`,
`subtype`, `kind`, `event`, `hook_name`, and `role` anywhere in the line,
skipping tool arguments and output (`input`, `arguments`, `args`,
`parameters`, `output`, `aggregated_output`, `tool_input`, `tool_response`).
Each value is split into lowercase words at punctuation and at a
lower-to-upper case change, so `item.completed`, `tool_use`, and `PreToolUse`
become `item` `completed`, `tool` `use`, and `pre` `tool` `use`. Matching is
on whole words, so `pending` does not match `end`.

| If the words include | Kind while running | Kind when completed |
| --- | --- | --- |
| `approval`, `approvals`, `permission`, or `permissions` | `approval.request` | `approval.decision` |
| `tool`, `tools`, `toolcall`, `toolcalls`, `tooluse`, `toolresult`, or `mcp`; or the adjacent pairs `command` `execution` or `function` `call` | `tool.invocation` | `tool.result` |
| `assistant`, `message`, or `messages` | `model.response` (`agent.message` for a user line) | `model.response` (`agent.message` for a user line) |
| `model` | `model.request` (`agent.message` for a user line) | `model.response` (`agent.message` for a user line) |
| `session`, `thread`, `agent`, `step`, or `turn` | `agent.turn` | `agent.result` |
| none of these | `provider.event` (`agent.message` for a user line) | `provider.event` (`agent.message` for a user line) |

A line counts as completed when the words include `completed`, `complete`,
`result`, `results`, `finish`, `finished`, `end`, or `ended`; or when the
line, its `item` or `part`, or their `state` has an exit code or a `status` /
`state` of `completed`, `complete`, `success`, `succeeded`, `done`, or
`finished`; or when it carries an approval decision.

Two more rules apply to every provider:

- **User messages.** A line whose `role`, or whose `message.role`, is `user`
  and that would otherwise be a model event or a `provider.event` is an
  `agent.message` with status `ok` and `payload.role: "user"`: what the user
  said is input to the agent, not something the model produced. A user line
  that carries tool results is still a `tool.result`.
- **Text beside tool calls.** An assistant message whose content has both a
  non-empty `text` block and tool blocks becomes a `model.response` for the
  message (with the whole line in `payload.native`, and its usage) followed
  by one tool event per tool block.

Examples from the fixtures: Codex `turn.started` is an `agent.turn`
(`turn_start`), a Codex `item.completed` whose item is an `agent_message` is
a `model.response`, an OpenCode `step_start` / `step_finish` pair is an
`agent.turn` / `agent.result`, and a Grok `session.completed` is an
`agent.result`.

### Failure

An event gets status `error` when the provider says so explicitly:

- `is_error` or `isError` is `true`;
- `status` or `state` is `error`, `errored`, `failed`, or `failure`;
- `exit_code` or `exitCode` is a non-zero integer;
- `error` is present and not `null`, empty, `false`, or `0`;
- or the event's own type (`type`, `subtype`, `event`, `kind`, `method`,
  `item.type`, `part.type`, or the nested block's `type`) has one of the
  whole words `error`, `errors`, `errored`, `fail`, `failed`, or `failure`,
  as in Codex `turn.failed` or a Claude `error_max_turns` result subtype.

These are read from the line, its `item` or `part`, their `state`, and the
nested tool block the event stands for. The text of tool arguments, tool
output, and model prose is never searched, so a tool that prints the word
"error" does not fail. A failure also ends the lifecycle: a failing tool line
is a `tool.result` even if the provider never says "completed".

A refusal is kept apart from a failure. When `status` or `state` is `denied`,
`rejected`, `declined`, or `blocked`, a tool event ends as a `tool.result`
with status `denied` rather than `error`. Other kinds of event with such a
status are `error`. The adapter only reports what the line states: Claude
marks a tool result it refused with `is_error` and prose, so that result is
`error`, and the refusal appears as an `approval.decision` (below).

Otherwise the status is `pending` for an `approval.request`, `ok` for
completed events and for any `*.response`, `*.result`, or `agent.message`,
and `running` for the rest.

### Approvals

For lines classified as approvals the adapter looks for a decision: a boolean
`approved`, `allowed`, or `granted`, or a string `decision`, `status`,
`state`, `outcome`, or `behavior`. Approve-like values give status `approved`;
deny-like values (`denied`, `deny`, `rejected`, `reject`, `declined`,
`blocked`) give status `denied`. A grant and a refusal are kept distinct
rather than folded into `ok` and `error`.

Claude Code does not print a line when it refuses a tool. Its final result
lists the refusals in `permission_denials`. Each entry becomes an
`approval.decision` with status `denied`, stored just before the result's
own `agent.result`:

- `correlation_id` and `span_id` are the entry's `tool_use_id`, the same id
  as the refused `tool.invocation`, which is also its `parent_event_id` and
  its only link when that call was recorded;
- `payload.tool` is the entry's `tool_name`;
- `payload.synthesized` is `true` and `payload.synthesized_from` is
  `permission_denials`, because the event is derived from a list rather than
  from a line of its own; `payload.native` is the list entry.

No `approval.request` is invented for it: the request really is absent from
the stream. Because the decision is marked `synthesized`, the validator does
not report the missing request as `missing_lifecycle_start`; a decision that
is not marked as inferred and has no request still is.

### Tool pairing

A tool call and its result are paired by a shared `correlation_id`. For tool
and approval events it is the first id found among `call_id`, `tool_use_id`,
`tool_call_id`, `tool_id`, `callID`, `toolCallId`, `toolUseId` on the line,
then on its `part`, then its `item`, then the nested tool block (or that
block's `id`), then `item.id` or `id`.

For other events the `correlation_id` is:

- the session id, for `agent.turn` and `agent.result` events of the main
  agent once a session id is known, so a session's start, its turns, and its
  result pair up through the session;
- otherwise the first of `call_id`, `tool_use_id`, `tool_call_id`, `item.id`,
  `message.id`, `request_id`, `uuid`, `id`, `session_id`, `thread_id` on the
  line, or empty.

- When one message carries several tool blocks (`message.content[]` or
  `content[]` entries whose `type` has a tool word, as defined under
  [Kind](#kind)), each block becomes its own `tool.invocation` or
  `tool.result` with its own id. A block whose type has the word `result` is
  a `tool.result`.
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

**Synthesized subagent lifecycle.** No provider line says "a subagent started"
or "a subagent finished". The adapter infers both and writes two events that
no line stands behind:

| Event | Written | Status |
| --- | --- | --- |
| `agent.spawn` | Just before the event for the first line that carries a new `parent_tool_use_id`. | `running` |
| `agent.result` | Just after the `tool.result` whose correlation id is that tool id, that is, when the spawning tool call returns. Once per subagent. | The status of that `tool.result`. |

Both have the subagent's `actor_id` and `actor_type`, `span_id` and
`correlation_id` set to the spawning tool id, and `parent_span_id` set to the
session id. Their payload marks them as inference and has no `native` copy:

| Payload field | Value |
| --- | --- |
| `synthesized` | `true` |
| `synthesized_from` | `parent_tool_use_id` for the spawn, `tool_result` for the result: the evidence the event was inferred from. |
| `parent_tool_use_id` | The spawning tool call's id. |
| `line` | The number of the stdout line being read when the event was written. |
| `tool` | The spawning tool's name, when the invocation was seen (for example `Task`). |
| `parent_actor` | Spawn only: the actor of its parent event, normally the spawning tool call. |
| `provider`, `adapter_schema_version` | As on every adapter event. |

If the stream ends before the spawning tool call returns, there is a spawn
and no result. Treat these two events as the adapter's reading of the stream,
not as something the provider reported.

### Parents and links

Adapter events carry `parent_event_id` and `links`. Both hold the `event_id`
of an event the adapter stored earlier in the same recording, so a parent
always precedes its child in the journal.

`parent_event_id` is the first of these candidates that has been stored:

| Event | Candidates, most specific first |
| --- | --- |
| `tool.result` | The `tool.invocation` with the same id. |
| `approval.request` | The tool call with the same id. |
| `approval.decision` | The `approval.request` with the same id, then the tool call with that id. |
| A hook line classified as `tool.invocation` (its type starts with `hook`, or it has `hook_name` or `hook_event_name`) | The tool call with the same id, when that call was stored first. |
| Synthesized `agent.spawn` | The spawning tool call. |
| Synthesized `agent.result` | The synthesized `agent.spawn`. Nothing else is tried. |
| Any event with `parent_tool_use_id` | Next, the subagent's synthesized `agent.spawn`. |
| Every event except a session start and a synthesized `agent.result` | Last, the open turn (unless the event opens a turn itself), then the session start. |

The session start is the latest `agent.turn` with `lifecycle:
"session_start"`. A turn is opened by any other `agent.turn` of the main
agent and closed by its next `agent.result`. The session start itself has no
parent, and when a stream has no session or turn line (Kimi, for example) an
event with no more specific candidate has no parent either.

`links` are added in these cases, when the target has been stored:

| Event | Links to |
| --- | --- |
| `tool.result` | Its `tool.invocation`. |
| `approval.decision` | Its `approval.request`. |
| `approval.decision` synthesized from `permission_denials` | The refused tool call. |
| Synthesized `agent.spawn` | The spawning tool call. |
| Synthesized `agent.result` | The synthesized `agent.spawn`, and the `tool.result` that ended the subagent. |

When a hook line and the tool call itself share an id, the call is the one
later events hang off, whichever came first.

The adapter remembers at most 4,096 stored event ids. Past that it forgets
every tool call, approval, and subagent and keeps only the session and the
open turn, so in a very long session a late result can fall back to the turn
as its parent.

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

- **Causality the stream does not imply.** `parent_event_id` and `links` come
  only from the rules under [Parents and links](#parents-and-links). Which
  model message led to which tool call, for example, is not derived.
- **Event time from the provider.** An adapter event is stamped with the time
  the recorder read the line. A provider time is kept only as
  `payload.native_timestamp`.
- **Prompt and response text as normalized fields.** They stay inside
  `payload.native` in the provider's own shape.
- **Token usage or cost the provider did not print.** Nothing is estimated
  from text or from a price table.
- **Tool duration**, unless the line has `duration_ms`.
- **Subagents, approvals, or model requests the CLI does not print.** If the
  CLI's JSON output has no line for something, there is no event for it. The
  exceptions are the synthesized subagent `agent.spawn` / `agent.result` pair
  and the `approval.decision` for each entry of `permission_denials`, all
  marked `payload.synthesized: true`.
- **Failure stated only in prose.** A tool result that says it failed only in
  its output text keeps status `ok`.
- **Anything from stderr or from an interactive UI.**

To add what an adapter cannot see, emit it from the harness with the
[SDK](../sdk/js/README.md) or the [collector](collector.md). Collector events
and adapter events share one journal.

## Redaction

Both the normalized events and the raw stdout copy are redacted; see
[redaction.md](redaction.md#adapter-runs).
