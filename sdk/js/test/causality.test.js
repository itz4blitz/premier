import { test } from "node:test";
import assert from "node:assert/strict";
import { emit, newId, premier, span } from "../dist/index.js";

let traces = 0;

/** A recording of its own, with a collector stub that stores what it is sent. */
function recording() {
  traces += 1;
  const bodies = [];
  const env = {
    PREMIER_TRACE_ID: `tr-causality-${traces}`,
    PREMIER_COLLECTOR_URL: "http://127.0.0.1:4318/v1/events",
    PREMIER_COLLECTOR_TOKEN: "secret",
  };
  const fetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    bodies.push(body);
    const sequence = bodies.length;
    await new Promise((resolve) => setImmediate(resolve));
    return {
      ok: true,
      async json() {
        return { ...body, event_id: `evt-${sequence}`, sequence };
      },
    };
  };
  return { bodies, options: { env, fetch } };
}

test("emit sends an empty object when the payload is omitted", async () => {
  const { bodies, options } = recording();
  await emit({ kind: "agent.spawn", actor_id: "researcher" }, options);
  await premier.spawn("coder", undefined, undefined, options);
  assert.deepEqual(bodies[0].payload, {});
  assert.deepEqual(bodies[1].payload, {});
});

test("the run block is sent only when a run variable is set", async () => {
  const { bodies, options } = recording();
  await emit({ kind: "agent.message" }, options);
  await emit({ kind: "agent.message" }, { ...options, env: { ...options.env, PREMIER_BRANCH: "main" } });
  assert.equal("run" in bodies[0], false);
  assert.deepEqual(bodies[1].run, { branch: "main" });
});

test("result names the same actor's spawn without being told", async () => {
  const { bodies, options } = recording();
  const spawned = await premier.spawn("researcher", { task: "find" }, {}, options);
  await premier.model("researcher", { model: "m" }, {}, options);
  await premier.result("researcher", { outcome: "done" }, {}, options);
  assert.equal(bodies[2].kind, "agent.result");
  assert.equal(bodies[2].parent_event_id, spawned.event_id);
  // A second result has no open spawn left to name.
  await premier.result("researcher", {}, {}, options);
  assert.equal("parent_event_id" in bodies[3], false);
});

test("result stays in the spawn's span and carries its correlation", async () => {
  const { bodies, options } = recording();
  await premier.spawn(
    "researcher",
    {},
    { span_id: "research", parent_span_id: "delegate", correlation_id: "ws" },
    options,
  );
  await premier.result("researcher", {}, {}, options);
  assert.equal(bodies[1].parent_event_id, "evt-1");
  assert.equal(bodies[1].span_id, "research");
  assert.equal(bodies[1].parent_span_id, "delegate");
  assert.equal(bodies[1].correlation_id, "ws");

  await premier.spawn("coder", {}, { span_id: "code" }, options);
  await premier.result("coder", {}, {}, options);
  assert.equal(bodies[3].span_id, "code");
  assert.equal("parent_span_id" in bodies[3], false, "a span is not its own parent");
});

test("a result that is not awaited after its spawn is still linked", async () => {
  const { bodies, options } = recording();
  const spawned = premier.spawn("researcher", {}, {}, options);
  const finished = premier.result("researcher", {}, {}, options);
  await Promise.all([spawned, finished]);
  assert.equal(bodies[1].parent_event_id, "evt-1");
  assert.equal(await premier.flush(), true);
});

test("explicit causality is never overridden", async () => {
  const { bodies, options } = recording();
  await premier.spawn("researcher", {}, {}, options);
  await premier.result("researcher", {}, { correlation_id: "mine" }, options);
  assert.equal(bodies[1].correlation_id, "mine");
  assert.equal("parent_event_id" in bodies[1], false);
});

test("join names the same actor's delegation", async () => {
  const { bodies, options } = recording();
  await premier.delegation("coordinator", { delegates: ["a"] }, {}, options);
  await premier.join("coordinator", { joined: ["a"] }, {}, options);
  assert.equal(bodies[1].parent_event_id, "evt-1");
});

test("approvalDecision names the request only when one is open", async () => {
  const { bodies, options } = recording();
  await premier.approval("coder", { operation: "write" }, {}, options);
  await premier.approvalDecision("brad", {}, {}, options);
  assert.equal(bodies[1].parent_event_id, "evt-1");

  const first = await premier.approval("coder", { operation: "write" }, {}, options);
  await premier.approval("coder", { operation: "delete" }, {}, options);
  await premier.approvalDecision("brad", {}, {}, options);
  assert.equal("parent_event_id" in bodies[4], false, "two open requests are ambiguous");
  // Naming one request leaves the other as the single open one.
  await premier.approvalDecision("brad", {}, first, options);
  assert.equal(bodies[5].parent_event_id, first.event_id);
  await premier.approvalDecision("brad", {}, {}, options);
  assert.equal(bodies[6].parent_event_id, "evt-4");
});

test("a helper accepts the prior event, or null, in place of extra", async () => {
  const { bodies, options } = recording();
  const spawned = await premier.spawn("researcher", {}, { span_id: "research" }, options);
  await premier.tool("researcher", { tool: "rg" }, spawned, options);
  await premier.tool("researcher", { tool: "rg" }, null, options);
  assert.equal(bodies[1].parent_event_id, spawned.event_id);
  assert.equal(bodies[1].parent_span_id, "research");
  assert.equal(bodies[1].status, "ok");
  assert.equal("parent_event_id" in bodies[2], false);
});

test("an actor keeps the actor_type it was spawned with", async () => {
  const { bodies, options } = recording();
  await premier.spawn("researcher", {}, {}, options);
  await premier.model("researcher", {}, {}, options);
  await premier.tool("researcher", {}, {}, options);
  await premier.tool("coder", {}, {}, options);
  await premier.tool("researcher", {}, { actor_type: "agent" }, options);
  assert.deepEqual(
    bodies.map((body) => body.actor_type),
    ["subagent", "subagent", "subagent", "agent", "agent"],
  );
});

test("a span carries actor, type, span and parent on every event", async () => {
  const { bodies, options } = recording();
  const coordinator = span("coordinator", { span_id: "delegate", correlation_id: "ws" });
  await coordinator.delegation({ delegates: ["researcher"] }, {}, options);
  const research = coordinator.child("researcher", { actor_type: "subagent" });
  await research.spawn({ task: "find" }, {}, options);
  await research.tool({ tool: "rg" }, {}, options);
  await research.emit({ kind: "tool.error", status: "error", payload: { tool: "rg" } }, options);
  await research.result({}, { status: "failed" }, options);
  await coordinator.join({}, {}, options);

  assert.match(research.span_id, /^span-/);
  for (const body of bodies.slice(1, 5)) {
    assert.equal(body.actor_id, "researcher");
    assert.equal(body.actor_type, "subagent");
    assert.equal(body.span_id, research.span_id);
    assert.equal(body.parent_span_id, "delegate");
    assert.equal(body.correlation_id, "ws");
  }
  assert.equal(bodies[3].kind, "tool.error");
  assert.equal(bodies[4].status, "failed");
  assert.equal(bodies[5].span_id, "delegate");
  assert.equal(bodies[5].actor_type, "agent");
});

test("a span whose parent is an event is that event's child", async () => {
  const { options } = recording();
  const spawned = await premier.spawn("researcher", {}, { span_id: "research", correlation_id: "ws" }, options);
  const patch = span("researcher", { parent: spawned, span_id: "patch" });
  assert.deepEqual(patch.fields({ status: "error" }), {
    actor_type: "agent",
    span_id: "patch",
    parent_span_id: "research",
    parent_event_id: spawned.event_id,
    correlation_id: "ws",
    status: "error",
  });
  assert.equal(span("x", { parent: null }).parent_event_id, undefined);
});

test("newId returns distinct prefixed ids", () => {
  const first = newId();
  assert.match(first, /^span-.{8,}$/);
  assert.notEqual(first, newId());
  assert.match(newId("corr"), /^corr-/);
});

test("helpers stay inert when Premier is not recording", async () => {
  const options = { env: {} };
  assert.equal(await premier.spawn("researcher", {}, {}, options), null);
  assert.equal(await premier.result("researcher", {}, {}, options), null);
  assert.equal(await span("researcher").tool({}, {}, options), null);
});
