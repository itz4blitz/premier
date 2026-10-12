# @premierstudio/trace

Minimal first-party emitter for [Premier](https://github.com/PremierStudio/premier) agent traces.

## Install

```sh
npm install @premierstudio/trace
# from a source checkout:
npm install ./sdk/js
```

Requires Node.js 18 or later. The package is ES modules only and has no
dependencies; `require("@premierstudio/trace")` works on Node.js versions that
can `require` an ES module (22.12 and later). Its type declarations do not
need `@types/node`.

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

Nothing in the example threads an id by hand: `premier.result` names the
`premier.spawn` of the same actor on its own (see [Causality](#causality)).
The examples in this file are run under `premier record` and checked with
`premier verify` by the package's tests, so they produce no diagnostics.

## API

| Export | Description |
| --- | --- |
| `emit(event, options?)` | Send one event. Resolves to the stored event, or `null`. |
| `premier` | The helpers below, plus `premier.emit`, `premier.flush`, `premier.childOf`, `premier.span`, `premier.newId`, and `premier.isActive`. |
| `flush(options?)` | Wait for emits that were not awaited. See [Emits that are not awaited](#emits-that-are-not-awaited). |
| `span(actor, init?)` | Helpers bound to one actor and one span. See [Spans](#spans). |
| `childOf(parent, extra?)` | Build the causality fields that make a new event a child of `parent`. |
| `newId(prefix?)` | A new unique id for `span_id` or `correlation_id` (`span-…` by default). |
| `isPremierActive(env?)` | `true` when both `PREMIER_COLLECTOR_URL` and `PREMIER_COLLECTOR_TOKEN` are set. |
| `premierEnv(env?)` | Returns `{ traceId, collectorUrl, collectorToken }`, or throws `PremierNotActiveError`. |
| `premierStats()` | `{ delivered, dropped, truncated }` counts for this process. |
| `PremierNotActiveError` | Thrown when the collector variables are absent and the caller asked for them. |
| `DEFAULT_EMIT_TIMEOUT_MS` | `5000`. |
| `MAX_EVENT_BYTES` | `2097152` (2 MiB), the local collector's request body limit. |
| `PremierEventInput`, `PremierEvent`, `PremierEmitOptions`, `PremierHelperExtra`, `PremierSpan`, `PremierSpanInit`, `PremierKind`, `PremierKnownKind`, `PremierEnv` | Types. |

### `emit(event, options?)`

`event` fields:

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | `PremierKind` | Required. Any string of ASCII letters, digits, `.`, `_`, `:`, `-`, at most 128 bytes. The type lists the kinds Premier knows (`PremierKnownKind`) for editor completion and accepts any other string. |
| `source` | `string` | Defaults to `"premier-sdk"`. Same character rule as `kind`. |
| `actor_id`, `actor_type` | `string` | `actor_type` follows the `kind` rule. `actor_id` is free text: at most 256 bytes, no control characters. |
| `status` | `string` | Free text, as `actor_id`. |
| `parent_event_id`, `span_id`, `parent_span_id`, `correlation_id` | `string` | Causality. Free text, as `actor_id`. |
| `links` | `string[]` | Each entry is free text, as `actor_id`. |
| `duration_ms` | `number` | Rounded to the nearest integer and clamped to zero or above, because the collector stores an unsigned integer. A non-finite value is dropped. |
| `payload` | `Record<string, unknown>` | Defaults to `{}`. See [Large payloads](#large-payloads). |
| `timestamp` | `string` | RFC 3339 producer time. It does not set the stored event's `timestamp`, which is always the recorder's receipt time; the local recorder keeps your value as `payload.producer_timestamp`. A value that is not RFC 3339 is rejected with `400`. |

The character and length rules are enforced by the local collector, not by
the SDK: an event that breaks one is rejected with `400`, which `emit` reports
like any other delivery failure. The full rules are in
[docs/collector.md](../../docs/collector.md#field-rules).

The SDK adds `trace_id` (from `PREMIER_TRACE_ID`) to each request; the local
collector answers `409` when it names a different recording. When any of
`PREMIER_RUN_NAME`, `PREMIER_REPOSITORY`, `PREMIER_BRANCH`,
`PREMIER_ENVIRONMENT`, or `PREMIER_STARTED_AT` is set, the SDK also adds a
`run` object holding the ones that are. The local collector accepts `run` and
stores none of it.

`emit` resolves to the event as the collector stored it, including the
`event_id`, `sequence`, and receipt `timestamp` it assigned, or to `null` when
nothing was stored.

### Options

The same object is accepted by `emit` and, as the fourth argument, by every
helper.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `required` | `boolean` | `false` | Throw instead of resolving to `null`. See [Failure handling](#failure-handling). |
| `timeoutMs` | `number` | `5000` | Give up after this many milliseconds. `0` or `Infinity` disables the timeout. |
| `signal` | `AbortSignal` | | Caller-owned cancellation, combined with the timeout. |
| `onError` | `(error, event) => void` | | Called with every swallowed delivery failure. |
| `env` | `PremierEnv` | `process.env` | Where the `PREMIER_*` variables are read from. |
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

An actor keeps the `actor_type` it was spawned with: after
`premier.spawn("researcher")`, `premier.model("researcher")` and
`premier.tool("researcher")` are written as `subagent` too, unless `extra`
says otherwise.

`extra` is a partial event. It overrides the default `actor_type` and `status`
and carries the causality fields, `source`, `duration_ms`, and `timestamp`
(the producer time, kept as `payload.producer_timestamp`). In its place a
helper also accepts the event the new one follows, as returned by `emit` or
another helper (`null` included): `premier.tool("coder", {}, spawned)` is
`premier.tool("coder", {}, premier.childOf(spawned))`.

**Precedence.** A helper builds its event in this order, later entries
winning:

1. the helper's default `actor_type` and `status`;
2. the `actor_type` the actor was spawned with, and for `result`, `join`, and
   `approvalDecision` the link to the event they complete (see
   [Causality](#causality));
3. every field of `extra` whose value is not `undefined`;
4. the positional arguments: the helper's `kind`, `actor` (as `actor_id`), and
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
`correlation_id`, and `links`.

**The completing half of a pair links itself.** When `extra` carries none of
those five fields:

| Helper | Is linked to |
| --- | --- |
| `premier.result(actor)` | the open `premier.spawn` of the same actor |
| `premier.join(actor)` | the open `premier.delegation` of the same actor |
| `premier.approvalDecision(decider)` | the open `premier.approval`, when exactly one is open |

Linked means `parent_event_id` is the start's `event_id`, and the start's
`span_id`, `parent_span_id`, and `correlation_id` are carried over, so the
finish sits in the same span as its start. A start is open from the
call that emits it until the helper that completes it; a start that was not
stored cannot be linked to. With two or more approvals open a decision could
answer either, so it is left unlinked: pass the request it answers. The helpers
remember this per recording, in the process that emitted the start.

When `extra` carries any causality field it is used as given and nothing is
added.

**Everything else is linked by you**, in one of three ways:

- pass the event the new one follows as `extra`;
- pass `childOf(parent, extra?)` to add or override fields: `parent_event_id`
  is `parent.event_id`, `parent_span_id` is `parent.span_id` and
  `correlation_id` is `parent.correlation_id` when the parent has them, and
  fields in `extra` are applied last. `childOf(null)` returns just `extra`;
- use a [span](#spans).

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
await premier.tool("researcher", { tool: "rg" }, spawned);

const request = await premier.approval(
  "researcher",
  { operation: "write", files: ["src/billing/ledger.ts"] },
  premier.childOf(spawned, { span_id: "patch-approval" }),
);
await premier.approvalDecision("brad", { receipt: "apr_01J" }, request);

await premier.result("researcher", { outcome: "patched" });
await premier.join("coordinator", { joined: ["researcher"] });
```

### Spans

`span(actor, init?)` returns the helpers bound to one actor and one unit of
work. Every event emitted through it carries the span's `actor_id`,
`actor_type`, `span_id`, and, when it has a parent, `parent_span_id`,
`parent_event_id`, and `correlation_id`.

| `init` field | Default | Meaning |
| --- | --- | --- |
| `actor_type` | `"agent"` | Written on every event of the span. |
| `span_id` | `newId()` | The span's id. |
| `parent` | | The event, or the span, this span descends from. A parent event gives `parent_event_id`, `parent_span_id`, and `correlation_id`; a parent span gives its `span_id` as `parent_span_id`, and its own `parent_event_id` and `correlation_id`. |
| `correlation_id` | the parent's | Shared by related spans. |

A span has `delegation`, `spawn`, `result`, `join`, `message`, `model`,
`tool`, and `approval`, each taking `(payload?, extra?, options?)`;
`emit(event, options?)` for any other kind; `child(actor, init?)` for a span
whose parent is this one; `fields(extra?)` for the causality fields
themselves; and the read-only `actor`, `actor_type`, `span_id`,
`parent_span_id`, `parent_event_id`, and `correlation_id`.

```ts
import { span } from "@premierstudio/trace";

const coordinator = span("coordinator", { correlation_id: "workstream-repair" });
await coordinator.delegation({ delegates: ["researcher"] });

const research = coordinator.child("researcher", { actor_type: "subagent" });
await research.spawn({ task: "find the first divergence" });
await research.model({ provider: "openai", model: "gpt-5" }, { duration_ms: 840 });
await research.emit({ kind: "tool.error", status: "error", payload: { tool: "rg", exit_code: 2 } });
await research.result({ outcome: "round before lock" });

await coordinator.join({ joined: ["researcher"] });
```

### Emits that are not awaited

An `emit` or helper call that is not awaited is still delivered: the pending
request keeps the process alive until it settles. The exception is
`process.exit()`, which ends the process with requests still in flight and
loses them. Call `flush()` first:

```ts
import { flush, premier } from "@premierstudio/trace";

void premier.tool("coder", { tool: "rg" }); // not awaited
await flush();
process.exitCode = 0; // or process.exit(0), now that nothing is in flight
```

`flush(options?)` waits for every emit that has been started, including ones
started while it waits, and never rejects. It resolves to `true` when nothing
is left in flight. With `{ timeoutMs }` it gives up after that long and
resolves to `false`. Each emit is still bounded by its own `timeoutMs`.

The SDK sends one request per event and does not batch or retry.

### Large payloads

The local collector refuses a request body over 2 MiB (`MAX_EVENT_BYTES`) with
`413`. Rather than lose such an event, the SDK shortens its payload before
sending:

- the longest strings in the payload, at any depth, are cut to what fits, each
  keeping at least its first 1024 characters and ending in
  `...[truncated by the Premier SDK]`;
- `payload.premier_truncated` records `original_bytes`, `limit_bytes`, and the
  `fields` that were shortened (dotted paths, at most 20 listed);
- a payload that long strings do not account for (a very large array of
  numbers, say) is replaced by
  `{ "premier_truncated": { "original_bytes": …, "limit_bytes": …, "fields": [], "payload": "dropped" } }`.

The event's other fields are sent unchanged, and the object you passed is not
modified. The first truncation in a process is reported once through
`console.warn`; `premierStats().truncated` counts them all.

### Failure handling

Telemetry never crashes or stalls your agent. `emit` and every helper resolve
to `null`, without throwing, when:

- Premier is not recording (the collector env is absent);
- the collector is unreachable or rejects the event (`400` for an invalid
  field, `401`, `408`, `409` for another recording's `trace_id`, `422` for a
  reserved kind or source, `500`, …);
- the collector does not answer within `timeoutMs` (default 5000 ms);
- `signal` is aborted.

Delivery failures (every case except "not recording") are passed to
`onError(error, event)`. Without `onError`, the first failure in the process
is reported once through `console.warn` and later ones are silent;
`premierStats().dropped` counts them all. An exception thrown by `onError`
itself is swallowed.

```ts
const abortController = new AbortController();
await premier.tool("coder", { tool: "rg" }, {}, {
  timeoutMs: 1000, // 0 disables the timeout
  signal: abortController.signal, // optional caller cancellation
  onError: (error, event) => console.debug("premier emit failed", event.kind, error),
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

## Collectors other than `premier record`

This repository implements one collector: the loopback endpoint that
`premier record` starts and injects as `PREMIER_COLLECTOR_URL`. The SDK posts
to whatever URL that variable names, so it can be pointed at another service
that speaks the same [wire contract](../../docs/collector.md), but no such
service is part of this repository and none is described here.

Two things to know before doing that: the SDK does not redact anything
(redaction is done by the recorder when it stores an event), so payloads leave
the machine as you built them; and the bearer token in
`PREMIER_COLLECTOR_TOKEN` is sent with every request.

## CLI alternative

Without Node.js, emit from a shell with the `premier` binary. `emit` prints
the stored event's id, which the next event can name:

```sh
spawned="$(premier emit --kind agent.spawn --actor researcher --actor-type subagent --status running)"
premier emit --kind tool.execution --actor researcher --actor-type subagent --status ok \
  --parent-event "$spawned" --duration-ms 120 --payload '{"tool":"rg"}'
premier emit --kind agent.result --actor researcher --actor-type subagent --status ok \
  --parent-event "$spawned"
```

`--payload` defaults to `{}`. All flags are listed in
[docs/cli.md](../../docs/cli.md#emit).

Where the `premier` binary is not available (a container that can reach the
collector, for instance), `premier-emit.sh` posts a JSON event with `bash` and
`curl` alone. It is a single file: `sdk/shell/premier-emit.sh` in the
repository, and `share/premier/premier-emit.sh` in every release archive
(`scripts/install.sh` installs it to `<prefix>/share/premier/`). See
[docs/collector.md](../../docs/collector.md#sdkshellpremier-emitsh).

`premier emit` and `premier-emit.sh` exit non-zero when the collector is
unreachable or rejects the event, and wait at most `PREMIER_EMIT_TIMEOUT`
seconds (default 10). For a loopback collector they never send the collector
token through `HTTP(S)_PROXY`.
