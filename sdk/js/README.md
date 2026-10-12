# @premierstudio/trace

Minimal first-party emitter for [Premier](https://github.com/PremierStudio/premier) agent traces.

## Install

```sh
npm install @premierstudio/trace
# from a source checkout:
npm install ./sdk/js
```

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

### Helpers

Every helper takes `(actor, payload, extra?, options?)` and returns the stored
event (or `null`). `extra` overrides the default `actor_type` / `status` and
carries causality fields; `options` is the same object `emit` accepts.

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

### Causality

Events are linked by `parent_event_id`, `span_id`, `parent_span_id`,
`correlation_id`, and `links`, all passed through `extra`. `premier.childOf`
derives the parent fields from an event you already emitted, and accepts the
`null` returned when Premier is not recording:

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

Telemetry never crashes or stalls your agent. `emit` and every helper return
`null`, without throwing, when:

- Premier is not recording (the collector env is absent);
- the collector is unreachable or rejects the event (`401`, `400`, `500`, …);
- the collector does not answer within `timeoutMs` (default 5000 ms).

Delivery failures are passed to `onError(error, event)`. Without `onError`, the
first failure in the process is reported once through `console.warn` and later
ones are silent.

```ts
await premier.tool("coder", { tool: "rg" }, {}, {
  timeoutMs: 1000, // 0 disables the timeout
  signal: abortController.signal, // optional caller cancellation
  onError: (error, event) => logger.debug({ error, kind: event.kind }, "premier emit failed"),
});
```

Pass `{ required: true }` to throw in all of the cases above instead, for
example in a test that asserts evidence was recorded.

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
is unreachable or rejects the event, wait at most `PREMIER_EMIT_TIMEOUT` seconds
(default 10), and never send the collector token through `HTTP(S)_PROXY`.
