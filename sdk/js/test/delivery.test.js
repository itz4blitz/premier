import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { emit, flush, MAX_EVENT_BYTES, premier, premierStats } from "../dist/index.js";

const ENV = {
  PREMIER_TRACE_ID: "tr-delivery",
  PREMIER_COLLECTOR_URL: "http://127.0.0.1:4318/v1/events",
  PREMIER_COLLECTOR_TOKEN: "secret",
};

function stored(body, sequence = 1) {
  return { ok: true, async json() { return { ...body, event_id: `evt-${sequence}`, sequence }; } };
}

const bytes = (text) => new TextEncoder().encode(text).length;

async function withSilencedWarnings(run) {
  const original = console.warn;
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(" "));
  try {
    await run();
  } finally {
    console.warn = original;
  }
  return warnings;
}

test("flush waits for emits that were not awaited", async () => {
  const delivered = [];
  const slow = async (_url, init) => {
    await new Promise((resolve) => setTimeout(resolve, 30));
    delivered.push(JSON.parse(init.body).kind);
    return stored({});
  };
  void emit({ kind: "tool.execution" }, { env: ENV, fetch: slow });
  void premier.tool("coder", {}, {}, { env: ENV, fetch: slow });
  assert.deepEqual(delivered, []);
  assert.equal(await flush(), true);
  assert.deepEqual(delivered.sort(), ["tool.execution", "tool.execution"]);
  assert.equal(await flush(), true, "flush with nothing in flight resolves at once");
});

test("flush never rejects and reports an expired wait", async () => {
  const errors = [];
  const failing = async () => {
    await new Promise((resolve) => setTimeout(resolve, 10));
    throw new TypeError("fetch failed");
  };
  void emit({ kind: "tool.execution" }, { env: ENV, fetch: failing, onError: (error) => errors.push(error) });
  assert.equal(await flush(), true);
  assert.equal(errors.length, 1);

  let release;
  const stalled = () => new Promise((resolve) => { release = () => resolve(stored({})); });
  const pending = emit({ kind: "tool.execution" }, { env: ENV, fetch: stalled, timeoutMs: 0 });
  assert.equal(await flush({ timeoutMs: 20 }), false);
  release();
  await pending;
  assert.equal(await flush({ timeoutMs: 20 }), true);
});

test("flush also waits for a rejected required emit", async () => {
  const failing = async () => {
    await new Promise((resolve) => setTimeout(resolve, 10));
    throw new TypeError("fetch failed");
  };
  const pending = emit({ kind: "tool.execution" }, { env: ENV, fetch: failing, required: true });
  pending.catch(() => {});
  assert.equal(await flush(), true);
  await assert.rejects(pending, /fetch failed/);
});

test("an oversized payload is shortened to fit the collector limit", async () => {
  const sent = [];
  const fetch = async (_url, init) => {
    sent.push(init.body);
    return stored({});
  };
  const payload = {
    response: "r".repeat(MAX_EVENT_BYTES),
    nested: { transcript: ["é".repeat(600_000), "short"] },
    count: 3,
  };
  const before = premierStats();
  const warnings = await withSilencedWarnings(async () => {
    assert.notEqual(await emit({ kind: "model.response", actor_id: "coder", payload }, { env: ENV, fetch }), null);
    await emit({ kind: "model.response", payload }, { env: ENV, fetch });
  });
  assert.ok(bytes(sent[0]) <= MAX_EVENT_BYTES, `sent ${bytes(sent[0])} bytes`);
  const body = JSON.parse(sent[0]);
  assert.equal(body.kind, "model.response");
  assert.equal(body.actor_id, "coder");
  assert.equal(body.payload.count, 3);
  assert.equal(body.payload.nested.transcript[1], "short");
  assert.match(body.payload.response, /^r+\.\.\.\[truncated by the Premier SDK\]$/);
  assert.ok(body.payload.premier_truncated.original_bytes > MAX_EVENT_BYTES);
  assert.equal(body.payload.premier_truncated.limit_bytes, MAX_EVENT_BYTES);
  assert.ok(body.payload.premier_truncated.fields.includes("response"));
  // The caller's object is untouched.
  assert.equal(payload.response.length, MAX_EVENT_BYTES);
  assert.equal(warnings.length, 1, "truncation is warned about once per process");
  assert.match(warnings[0], /shortened/);
  assert.equal(premierStats().truncated - before.truncated, 2);
});

test("a payload that cannot be shortened is replaced by a note", async () => {
  const sent = [];
  const fetch = async (_url, init) => {
    sent.push(init.body);
    return stored({});
  };
  const payload = { rows: Array.from({ length: 300_000 }, (_, index) => index + 1_000_000) };
  await withSilencedWarnings(() => emit({ kind: "tool.execution", status: "ok", payload }, { env: ENV, fetch }));
  assert.ok(bytes(sent[0]) <= MAX_EVENT_BYTES);
  const body = JSON.parse(sent[0]);
  assert.equal(body.status, "ok");
  assert.equal(body.payload.premier_truncated.payload, "dropped");
  assert.ok(body.payload.premier_truncated.original_bytes > MAX_EVENT_BYTES);
});

test("a body at the limit is sent unchanged", async () => {
  const sent = [];
  const fetch = async (_url, init) => {
    sent.push(init.body);
    return stored({});
  };
  const payload = { text: "x".repeat(MAX_EVENT_BYTES - 4096) };
  await emit({ kind: "tool.execution", payload }, { env: ENV, fetch });
  assert.equal(JSON.parse(sent[0]).payload.text.length, payload.text.length);
  assert.equal("premier_truncated" in JSON.parse(sent[0]).payload, false);
});

test("premierStats counts deliveries and drops", async () => {
  const before = premierStats();
  await emit({ kind: "tool.execution" }, { env: ENV, fetch: async () => stored({}) });
  await emit(
    { kind: "tool.execution" },
    { env: ENV, fetch: async () => ({ ok: false, status: 413, statusText: "", async text() { return "too large"; } }), onError() {} },
  );
  await emit({ kind: "tool.execution" }, { env: {} });
  const after = premierStats();
  assert.equal(after.delivered - before.delivered, 1);
  assert.equal(after.dropped - before.dropped, 1);
});

test("the package resolves for import, require and bare default conditions", async () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const entry = manifest.exports["."];
  assert.equal(entry.types, "./dist/index.d.ts");
  assert.equal(entry.import, "./dist/index.js");
  assert.equal(entry.default, "./dist/index.js");
  assert.deepEqual(Object.keys(entry), ["types", "import", "default"], "types first, default last");
  assert.equal(manifest.dependencies, undefined, "the SDK has no runtime dependencies");

  const require = createRequire(import.meta.url);
  // Resolution through the package name exercises the exports map itself.
  assert.match(require.resolve("@premierstudio/trace"), /sdk[\\/]js[\\/]dist[\\/]index\.js$/);
  const viaName = await import("@premierstudio/trace");
  assert.equal(typeof viaName.emit, "function");
});

test("the published types do not need @types/node", () => {
  const types = readFileSync(new URL("../dist/index.d.ts", import.meta.url), "utf8");
  assert.doesNotMatch(types, /NodeJS\./);
  assert.doesNotMatch(types, /from "node:/);
  assert.doesNotMatch(types, /\bBuffer\b/);
});
