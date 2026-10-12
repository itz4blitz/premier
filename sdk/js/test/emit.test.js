import { test } from "node:test";
import assert from "node:assert/strict";
import { emit, isPremierActive, premier, premierEnv, PremierNotActiveError } from "../dist/index.js";

test("isPremierActive requires both collector env vars", () => {
  assert.equal(isPremierActive({}), false);
  assert.equal(
    isPremierActive({
      PREMIER_COLLECTOR_URL: "http://127.0.0.1:9/v1/events",
      PREMIER_COLLECTOR_TOKEN: "tok",
    }),
    true,
  );
});

test("premierEnv throws a clear error when inactive", () => {
  assert.throws(() => premierEnv({}), (err) => err instanceof PremierNotActiveError);
});

test("emit no-ops when inactive unless required", async () => {
  assert.equal(await emit({ kind: "agent.spawn" }, { env: {} }), null);
  await assert.rejects(
    () => emit({ kind: "agent.spawn" }, { env: {}, required: true }),
    PremierNotActiveError,
  );
});

test("emit posts JSON with bearer token", async () => {
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      async json() {
        return { event_id: "evt-1", trace_id: "tr-1", kind: "agent.spawn" };
      },
    };
  };
  const result = await emit(
    { kind: "agent.spawn", actor_id: "researcher", payload: { task: "find" } },
    {
      env: {
        PREMIER_TRACE_ID: "always-on-42",
        PREMIER_COLLECTOR_URL: "http://127.0.0.1:4318/v1/events",
        PREMIER_COLLECTOR_TOKEN: "secret",
        PREMIER_RUN_NAME: "Production support agent",
        PREMIER_REPOSITORY: "premier/support-agent",
        PREMIER_BRANCH: "main",
        PREMIER_ENVIRONMENT: "production",
      },
      fetch: fakeFetch,
    },
  );
  assert.equal(result.event_id, "evt-1");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:4318/v1/events");
  assert.equal(calls[0].init.headers.Authorization, "Bearer secret");
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.kind, "agent.spawn");
  assert.equal(body.actor_id, "researcher");
  assert.equal(body.source, "premier-sdk");
  assert.equal(body.trace_id, "always-on-42");
  assert.deepEqual(body.run, {
    name: "Production support agent",
    repository: "premier/support-agent",
    branch: "main",
    environment: "production",
  });
});

test("emit normalizes fractional and invalid duration_ms for the u64 collector", async () => {
  const env = {
    PREMIER_TRACE_ID: "tr",
    PREMIER_COLLECTOR_URL: "http://127.0.0.1:4318/v1/events",
    PREMIER_COLLECTOR_TOKEN: "secret",
  };
  const bodies = [];
  const fakeFetch = async (_url, init) => {
    bodies.push(JSON.parse(init.body));
    return { ok: true, async json() { return { event_id: "e", trace_id: "tr", kind: "k", sequence: 1 }; } };
  };
  await emit({ kind: "tool.execution", duration_ms: 12.75 }, { env, fetch: fakeFetch });
  await emit({ kind: "tool.execution", duration_ms: -3.2 }, { env, fetch: fakeFetch });
  await emit({ kind: "tool.execution", duration_ms: Number.POSITIVE_INFINITY }, { env, fetch: fakeFetch });
  assert.equal(bodies[0].duration_ms, 13);
  assert.equal(bodies[1].duration_ms, 0);
  assert.equal("duration_ms" in bodies[2], false);
});

const ACTIVE_ENV = {
  PREMIER_TRACE_ID: "tr",
  PREMIER_COLLECTOR_URL: "http://127.0.0.1:4318/v1/events",
  PREMIER_COLLECTOR_TOKEN: "secret",
};

function recordingFetch(bodies, reply = {}) {
  return async (_url, init) => {
    bodies.push(JSON.parse(init.body));
    return {
      ok: true,
      async json() {
        return { event_id: `evt-${bodies.length}`, trace_id: "tr", kind: "k", sequence: bodies.length, ...reply };
      },
    };
  };
}

const refused = async () => {
  throw new TypeError("fetch failed");
};

test("emit swallows transport failures by default and reports them through onError", async () => {
  const errors = [];
  const result = await emit(
    { kind: "tool.execution" },
    { env: ACTIVE_ENV, fetch: refused, onError: (error, event) => errors.push({ error, event }) },
  );
  assert.equal(result, null);
  assert.equal(errors.length, 1);
  assert.match(errors[0].error.message, /fetch failed/);
  assert.equal(errors[0].event.kind, "tool.execution");
  await assert.rejects(
    () => emit({ kind: "tool.execution" }, { env: ACTIVE_ENV, fetch: refused, required: true }),
    /fetch failed/,
  );
});

test("emit swallows collector rejections by default and throws them when required", async () => {
  const unauthorized = async () => ({
    ok: false,
    status: 401,
    statusText: "Unauthorized",
    async text() {
      return '{"error":"invalid collector token"}';
    },
  });
  const errors = [];
  assert.equal(
    await emit({ kind: "agent.spawn" }, { env: ACTIVE_ENV, fetch: unauthorized, onError: (error) => errors.push(error) }),
    null,
  );
  assert.match(errors[0].message, /rejected event \(401\).*invalid collector token/);
  await assert.rejects(
    () => emit({ kind: "agent.spawn" }, { env: ACTIVE_ENV, fetch: unauthorized, required: true }),
    /rejected event \(401\)/,
  );
});

test("emit never lets a throwing onError or an unserializable payload reach the agent", async () => {
  assert.equal(
    await emit(
      { kind: "tool.execution" },
      {
        env: ACTIVE_ENV,
        fetch: refused,
        onError: () => {
          throw new Error("handler bug");
        },
      },
    ),
    null,
  );
  const circular = {};
  circular.self = circular;
  const errors = [];
  assert.equal(
    await emit(
      { kind: "tool.execution", payload: circular },
      { env: ACTIVE_ENV, fetch: recordingFetch([]), onError: (error) => errors.push(error) },
    ),
    null,
  );
  assert.equal(errors.length, 1);
});

test("emit times out a collector that never answers", async () => {
  let seenSignal;
  const hang = (_url, init) => {
    seenSignal = init.signal;
    return new Promise(() => {});
  };
  const errors = [];
  const started = Date.now();
  const result = await emit(
    { kind: "tool.execution" },
    { env: ACTIVE_ENV, fetch: hang, timeoutMs: 40, onError: (error) => errors.push(error) },
  );
  assert.equal(result, null);
  assert.ok(Date.now() - started < 2000, "emit must resolve soon after the timeout");
  assert.ok(seenSignal instanceof AbortSignal);
  assert.equal(seenSignal.aborted, true);
  assert.match(errors[0].message, /did not respond within 40ms/);
  await assert.rejects(
    () => emit({ kind: "tool.execution" }, { env: ACTIVE_ENV, fetch: hang, timeoutMs: 40, required: true }),
    /did not respond within 40ms/,
  );
});

test("emit warns on the console once when no onError is given", async () => {
  const original = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  try {
    assert.equal(await emit({ kind: "tool.execution" }, { env: ACTIVE_ENV, fetch: refused }), null);
    assert.equal(await emit({ kind: "tool.execution" }, { env: ACTIVE_ENV, fetch: refused }), null);
  } finally {
    console.warn = original;
  }
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /Premier/);
});

test("helpers keep their defaults when extra carries undefined fields", async () => {
  const bodies = [];
  const options = { env: ACTIVE_ENV, fetch: recordingFetch(bodies) };
  await premier.tool("coder", { tool: "rg" }, { status: undefined, actor_type: undefined }, options);
  await premier.spawn("researcher", {}, { actor_type: undefined, status: undefined }, options);
  await premier.approval("coder", { operation: "write" }, { status: undefined }, options);
  await premier.model("coder", { model: "m" }, { status: "error", actor_type: "subagent", span_id: "s1" }, options);
  assert.deepEqual(
    bodies.map((body) => [body.kind, body.actor_id, body.actor_type, body.status]),
    [
      ["tool.execution", "coder", "agent", "ok"],
      ["agent.spawn", "researcher", "subagent", "running"],
      ["approval.request", "coder", "agent", "pending"],
      ["model.response", "coder", "subagent", "error"],
    ],
  );
  assert.equal(bodies[3].span_id, "s1");
  assert.deepEqual(bodies[0].payload, { tool: "rg" });
});

test("helpers pass emit options through", async () => {
  const inactive = { env: {}, required: true };
  await assert.rejects(() => premier.tool("coder", {}, {}, inactive), PremierNotActiveError);
  await assert.rejects(() => premier.spawn("coder", {}, {}, inactive), PremierNotActiveError);
  await assert.rejects(() => premier.model("coder", {}, {}, inactive), PremierNotActiveError);
  await assert.rejects(() => premier.approval("coder", {}, {}, inactive), PremierNotActiveError);
  const errors = [];
  assert.equal(
    await premier.tool("coder", {}, {}, { env: ACTIVE_ENV, fetch: refused, onError: (error) => errors.push(error) }),
    null,
  );
  assert.equal(errors.length, 1);
});

test("lifecycle helpers emit the completing half of each pair", async () => {
  const bodies = [];
  // A trace of its own: helpers remember what each actor of a trace spawned.
  const options = { env: { ...ACTIVE_ENV, PREMIER_TRACE_ID: "tr-lifecycle" }, fetch: recordingFetch(bodies) };
  await premier.delegation("coordinator", { delegates: ["researcher"] }, {}, options);
  await premier.message("researcher", { to: ["coordinator"], finding: "x" }, {}, options);
  await premier.approvalDecision("brad", { receipt: "apr_01J" }, {}, options);
  await premier.approvalDecision("brad", {}, { status: "denied" }, options);
  await premier.result("researcher", { outcome: "done" }, {}, options);
  await premier.join("coordinator", { joined: ["researcher"] }, {}, options);
  assert.deepEqual(
    bodies.map((body) => [body.kind, body.actor_id, body.actor_type, body.status]),
    [
      ["agent.delegation", "coordinator", "agent", "running"],
      ["agent.message", "researcher", "agent", "ok"],
      ["approval.decision", "brad", "human", "approved"],
      ["approval.decision", "brad", "human", "denied"],
      ["agent.result", "researcher", "subagent", "ok"],
      ["agent.join", "coordinator", "agent", "ok"],
    ],
  );
});

test("childOf threads causality from a stored event and tolerates null", async () => {
  assert.deepEqual(premier.childOf(null), {});
  assert.deepEqual(
    premier.childOf({
      event_id: "evt-1",
      trace_id: "tr",
      kind: "agent.spawn",
      sequence: 1,
      span_id: "research",
      correlation_id: "ws",
    }),
    { parent_event_id: "evt-1", parent_span_id: "research", correlation_id: "ws" },
  );
  assert.deepEqual(
    premier.childOf(
      { event_id: "evt-2", trace_id: "tr", kind: "agent.spawn", sequence: 2, span_id: "", correlation_id: "" },
      { span_id: "patch" },
    ),
    { parent_event_id: "evt-2", span_id: "patch" },
  );
  const bodies = [];
  const options = { env: ACTIVE_ENV, fetch: recordingFetch(bodies, { span_id: "research" }) };
  const spawned = await premier.spawn("researcher", {}, { span_id: "research" }, options);
  await premier.tool("researcher", { tool: "rg" }, premier.childOf(spawned, { span_id: "search" }), options);
  assert.equal(bodies[1].parent_event_id, "evt-1");
  assert.equal(bodies[1].parent_span_id, "research");
  assert.equal(bodies[1].span_id, "search");
});
