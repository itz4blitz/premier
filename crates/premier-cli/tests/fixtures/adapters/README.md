# Adapter fixtures

These files are **hand-written**. They were composed from knowledge of each CLI's
structured stream format and are **not captured from real runs**: ids, models, token
counts, costs and timestamps are invented, and a real stream may carry fields these
omit or shape them differently. Treat them as regression inputs for the normalizer,
not as a specification of any provider's output.

Each file walks one short session: session start, a model message, a tool call with
its result, a failed tool, and usage or a final result, as far as that provider's
stream has such lines.

| File | Stream it imitates | Notes |
| --- | --- | --- |
| `claude.jsonl` | `claude -p --output-format stream-json --verbose` | Includes a `PreToolUse` hook line and a `Task` subagent (`parent_tool_use_id`). |
| `codex.jsonl` | `codex exec --json` | `thread.started`, `turn.*`, `item.*`. |
| `gemini.jsonl` | `gemini --output-format stream-json` | Every line carries an RFC 3339 `timestamp`. |
| `opencode.jsonl` | `opencode run --format json` | Epoch-millisecond `timestamp`; a tool appears once, already completed or failed. |
| `kimi.jsonl` | `kimi --print --output-format stream-json` | Role-keyed messages with no session or result line. One failed tool is stated only in its result text, which the adapter does not interpret (it stays `ok`); another adds an explicit `is_error` to exercise the failure path. |
| `grok.jsonl` | `grok --output-format streaming-json` | The least certain of the set: event names follow the dotted style the adapter already accepted. |
| `droid.jsonl` | `droid exec --output-format json` | A single result object preceded by terminal control sequences. That is the whole stream in this mode, so it is not extended. |

Never regenerate these by running a real agent CLI from the test suite.
