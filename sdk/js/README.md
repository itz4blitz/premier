# @premierstudio/trace

Minimal first-party emitter for [Premier](https://github.com/PremierStudio/premier) agent traces.

## Install

```sh
npm install @premierstudio/trace
# from a source checkout:
npm install ./sdk/js
```

Requires Node.js 18 or later. The package is ES modules only.

## Usage

Run your agent under `premier record` so the collector env is injected:

```sh
premier record -- node agent.js
```

```ts
import { emit, premier, isPremierActive } from "@premierstudio/trace";

if (isPremierActive()) {
  await premier.spawn("researcher", { task: "find the first divergence" });
  await premier.model("researcher", {
    provider: "openai",
    model: "gpt-5",
    usage: { input_tokens: 1200, output_tokens: 400, total_tokens: 1600 },
    response: "…",
  });
  await emit({
    kind: "tool.execution",
    actor_id: "coder",
    status: "ok",
    payload: { tool: "rg", query: "reconcileInvoice" },
  });
  await premier.result("researcher", { outcome: "round before lock" });
}
```

The `isPremierActive()` guard is optional. Every call is a no-op that returns
`null` when Premier is not recording.

## API

| Export | Description |
| --- | --- |
| `emit(event, options?)` | Send one event. Resolves to the stored event, or `null`. |
| `premier` | The helpers below, plus `premier.emit`, `premier.childOf`, and `premier.isActive`. |
| `childOf(parent, extra?)` | Build the causality fields that make a new event a child of `parent`. |
| `isPremierActive(env?)` | `true` when both `PREMIER_COLLECTOR_URL` and `PREMIER_COLLECTOR_TOKEN` are set. |
| `premierEnv(env?)` | Returns `{ traceId, collectorUrl, collectorToken }`, or throws `PremierNotActiveError`. |
| `PremierNotActiveError` | Thrown when the collector variables are absent and the caller asked for them. |
| `DEFAULT_EMIT_TIMEOUT_MS` | `5000`. |
| `PremierEventInput`, `PremierEvent`, `PremierEmitOptions` | Types. |

### `emit(event, options?)`

`event` fields:

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | `string` | Required. |
| `source` | `string` | Defaults to `"premier-sdk"`. |
| `actor_id`, `actor_type` | `string` | |
| `status` | `string` | |
| `parent_event_id`, `span_id`, `parent_span_id`, `correlation_id` | `string` | Causality. |
| `links` | `string[]` | |
| `duration_ms` | `number` | Rounded to the nearest integer and clamped to zero or above, because the collector stores an unsigned integer. A non-finite value is dropped. |
| `payload` | `Record<string, unknown>` | |
| `timestamp` | `string` | RFC 3339 producer time, stored verbatim. When omitted the collector records its own receipt time. |

The SDK adds `trace_id` (from `PREMIER_TRACE_ID`) and a `run` object (from
`PREMIER_RUN_NAME`, `PREMIER_REPOSITORY`, `PREMIER_BRANCH`,
`PREMIER_ENVIRONMENT`, `PREMIER_STARTED_AT`) to each request. The local
collector started by `premier record` ignores both.

`emit` resolves to the event as the collector stored it, including the
`event_id` and `sequence` it assigned, or to `null` when nothing was stored.

### Options

The same object is accepted by `emit` and, as the fourth argument, by every
helper.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `required` | `boolean` | `false` | Throw instead of resolving to `null`. See [Failure handling](#failure-handling). |
| `timeoutMs` | `number` | `5000` | Give up after this many milliseconds. `0` or `Infinity` disables the timeout. |
| `signal` | `AbortSignal` | | Caller-owned cancellation, combined with the timeout. |
| `onError` | `(error, event) => void` | | Called with every swallowed delivery failure. |
| `env` | `NodeJS.ProcessEnv` | `process.env` | Where the `PREMIER_*` variables are read from. |
| `fetch` | `typeof fetch` | `globalThis.fetch` | The fetch implementation to use. The timeout also bounds a custom one. |

### Helpers

Every helper takes `(actor, payload?, extra?, options?)` and resolves to the
stored event (or `null`). `payload` defaults to `{}`.

| Helper | Kind | Default `actor_type` / `status` |
| --- | --- | --- |
| `premier.delegation` | `agent.delegation` | `agent` / `running` |
| `premier.spawn` | `agent.spawn` | `subagent` / `running` |
| `premier.result` | `agent.result` | `subagent` / `ok` |
| `premier.join` | `agent.join` | `agent` / `ok` |
| `premier.message` | `agent.message` | `agent` / `ok` |
| `premier.model` | `model.response` | `agent` / `ok` |
| `premier.tool` | `tool.execution` | `agent` / `ok` |
| `premier.approval` | `approval.request` | `agent` / `pending` |
| `premier.approvalDecision` | `approval.decision` | `human` / `approved` |

Close what you open: `spawn` with `result`, `delegation` with `join`, and
`approval` with `approvalDecision` (pass `{ status: "denied" }` to refuse). Use
`emit` directly for any other kind.

`extra` is a partial event. It overrides the default `actor_type` and `status`
and carries the causality fields, `source`, `duration_ms`, and `timestamp`.

**Precedence.** A helper builds its event in this order, later entries
winning:

1. the helper's default `actor_type` and `status`;
2. every field of `extra` whose value is not `undefined`;
3. the positional arguments: the helper's `kind`, `actor` (as `actor_id`), and
   `payload`.

So the positional arguments always win. `extra.kind`, `extra.actor_id`, and
`extra.payload` are ignored, and `{ status: undefined }` in `extra` keeps the
default status instead of erasing it.

```ts
// Stored as kind "tool.execution", actor "coder", status "error".
await premier.tool("coder", { tool: "cargo test" }, { status: "error", kind: "ignored" });
```

### Causality

Events are linked by `parent_event_id`, `span_id`, `parent_span_id`,
`correlation_id`, and `links`, all passed through `extra`.

`childOf(parent, extra?)` derives the parent fields from an event you already
emitted:

- `parent_event_id` is `parent.event_id`;
- `parent_span_id` is `parent.span_id`, when the parent has one;
- `correlation_id` is `parent.correlation_id`, when the parent has one;
- fields in `extra` are added last and override the derived ones.

It accepts the `null` returned when Premier is not recording, and then returns
just `extra`.

```ts
const delegation = await premier.delegation(
  "coordinator",
  { delegates: ["researcher"] },
  { span_id: "delegate", correlation_id: "workstream-repair" },
);
const spawned = await premier.spawn(
  "researcher",
  { task: "find the first divergence" },
  premier.childOf(delegation, { span_id: "research" }),
);
// parent_event_id = spawned.event_id, parent_span_id = "research",
// correlation_id = "workstream-repair"
await premier.tool("researcher", { tool: "rg" }, premier.childOf(spawned));

const request = await premier.approval(
  "researcher",
  { operation: "write", files: ["src/billing/ledger.ts"] },
  premier.childOf(spawned, { span_id: "patch-approval" }),
);
await premier.approvalDecision("brad", { receipt: "apr_01J" }, premier.childOf(request));

await premier.result("researcher", { outcome: "patched" }, premier.childOf(spawned));
await premier.join("coordinator", { joined: ["researcher"] }, premier.childOf(delegation));
```

### Failure handling

Telemetry never crashes or stalls your agent. `emit` and every helper resolve
to `null`, without throwing, when:

- Premier is not recording (the collector env is absent);
- the collector is unreachable or rejects the event (`400`, `401`, `422`,
  `500`, …);
- the collector does not answer within `timeoutMs` (default 5000 ms);
- `signal` is aborted.

Delivery failures (every case except "not recording") are passed to
`onError(error, event)`. Without `onError`, the first failure in the process
is reported once through `console.warn` and later ones are silent. An
exception thrown by `onError` itself is swallowed.

```ts
await premier.tool("coder", { tool: "rg" }, {}, {
  timeoutMs: 1000, // 0 disables the timeout
  signal: abortController.signal, // optional caller cancellation
  onError: (error, event) => logger.debug({ error, kind: event.kind }, "premier emit failed"),
});
```

Pass `{ required: true }` to throw in all of the cases above instead, for
example in a test that asserts evidence was recorded. When Premier is not
recording the error is a `PremierNotActiveError`; otherwise it is the delivery
error, and `onError` is not called.

The collector rejects events that claim a kind or source reserved for the
recorder, such as `process.exit`. See
[docs/collector.md](../../docs/collector.md) for the wire contract and
[docs/events.md](../../docs/events.md) for the event vocabulary.

## Premier Cloud

Always-on and deployed agents can emit without a local `premier record` process. Create a project ingestion key in the Premier dashboard and set:

```sh
PREMIER_COLLECTOR_URL=https://premier.dev/api/ingest/v1/events
PREMIER_COLLECTOR_TOKEN=prem_ing_…
PREMIER_TRACE_ID=<unique-run-or-conversation-id>
PREMIER_RUN_NAME="Production support agent"
PREMIER_ENVIRONMENT=production
```

The SDK includes the trace identity and run metadata on every event. Optional
`PREMIER_REPOSITORY`, `PREMIER_BRANCH`, and `PREMIER_STARTED_AT` variables are
attached the same way. Store the ingestion key in a server-side secret manager;
never ship it to a browser.

## CLI alternative

```sh
premier emit --kind agent.spawn --actor researcher --status running
```

`premier emit` and `sdk/shell/premier-emit.sh` exit non-zero when the collector
is unreachable or rejects the event, and wait at most `PREMIER_EMIT_TIMEOUT`
seconds (default 10). For a loopback collector they never send the collector
token through `HTTP(S)_PROXY`.
