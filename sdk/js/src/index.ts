/**
 * Premier first-party emitter SDK.
 *
 * Under `premier record -- <command>`, the CLI injects:
 *   PREMIER_TRACE_ID, PREMIER_COLLECTOR_URL, PREMIER_COLLECTOR_TOKEN
 *
 * Call `emit(...)` from agent runtimes to attach typed multi-actor evidence.
 */

/**
 * The kinds Premier's validator and viewer know. Any other kind that follows
 * the collector's character rule is stored as given.
 */
export type PremierKnownKind =
  | "agent.spawn"
  | "agent.turn"
  | "agent.result"
  | "agent.delegation"
  | "agent.join"
  | "agent.message"
  | "model.request"
  | "model.response"
  | "tool.invocation"
  | "tool.result"
  | "tool.execution"
  | "tool.error"
  | "approval.request"
  | "approval.decision";

/** A known kind (offered by editors) or any other string. */
export type PremierKind = PremierKnownKind | (string & {});

/** Environment variables as the SDK reads them; `process.env` satisfies it. */
export type PremierEnv = Record<string, string | undefined>;

export type PremierEventInput = {
  kind: PremierKind;
  source?: string;
  actor_id?: string;
  actor_type?: string;
  parent_event_id?: string;
  span_id?: string;
  parent_span_id?: string;
  correlation_id?: string;
  status?: string;
  duration_ms?: number;
  links?: string[];
  /** Defaults to `{}`: the validator expects every payload to be an object. */
  payload?: Record<string, unknown>;
  /**
   * RFC3339 producer timestamp. The local recorder always stamps the event
   * `timestamp` with its own receipt time and keeps this value as
   * `payload.producer_timestamp`; anything that is not RFC3339 is rejected
   * with HTTP 400, as is a timestamp sent with a non-object payload.
   */
  timestamp?: string;
};

/**
 * Collector acknowledgement for one accepted event. `sequence` is the
 * collector-assigned journal order. The local recorder echoes the full stored
 * event (including `payload_json`); only the first four fields are required of
 * any other collector.
 */
export type PremierEvent = {
  event_id: string;
  trace_id: string;
  kind: string;
  sequence: number;
  timestamp?: string;
  source?: string;
  payload_json?: string;
  actor_id?: string;
  actor_type?: string;
  parent_event_id?: string;
  span_id?: string;
  parent_span_id?: string;
  correlation_id?: string;
  status?: string;
  duration_ms?: number;
  links?: string[];
};

export class PremierNotActiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PremierNotActiveError";
  }
}

export function isPremierActive(
  env: PremierEnv = process.env,
): boolean {
  return Boolean(env.PREMIER_COLLECTOR_URL && env.PREMIER_COLLECTOR_TOKEN);
}

export function premierEnv(env: PremierEnv = process.env): {
  traceId: string | undefined;
  collectorUrl: string;
  collectorToken: string;
} {
  const collectorUrl = env.PREMIER_COLLECTOR_URL;
  const collectorToken = env.PREMIER_COLLECTOR_TOKEN;
  if (!collectorUrl || !collectorToken) {
    throw new PremierNotActiveError(
      "Premier collector is not active. Run your process under `premier record -- <command>`.",
    );
  }
  return {
    traceId: env.PREMIER_TRACE_ID,
    collectorUrl,
    collectorToken,
  };
}

/** Default per-event request budget. Telemetry must never stall the agent. */
export const DEFAULT_EMIT_TIMEOUT_MS = 5000;

export type PremierEmitOptions = {
  /**
   * Throw instead of returning null when Premier is not recording, the
   * collector is unreachable or slow, or it rejects the event.
   */
  required?: boolean;
  env?: PremierEnv;
  fetch?: typeof fetch;
  /**
   * Abort the request after this many milliseconds (default
   * `DEFAULT_EMIT_TIMEOUT_MS`). `0` or `Infinity` disables the timeout.
   */
  timeoutMs?: number;
  /** Caller-owned cancellation, combined with the timeout. */
  signal?: AbortSignal;
  /**
   * Called with every swallowed delivery failure. When omitted, the first
   * failure in the process is reported once through `console.warn`.
   */
  onError?: (error: unknown, event: PremierEventInput) => void;
};

let warnedAboutFailure = false;
let warnedAboutTruncation = false;

const stats = { delivered: 0, dropped: 0, truncated: 0 };

/**
 * Counts for this process: events the collector stored, events dropped after
 * a delivery failure, and events stored with a shortened payload. Useful when
 * no `onError` is installed, because only the first drop is warned about.
 */
export function premierStats(): { delivered: number; dropped: number; truncated: number } {
  return { ...stats };
}

function reportFailure(
  error: unknown,
  event: PremierEventInput,
  options: PremierEmitOptions,
): void {
  stats.dropped += 1;
  try {
    if (options.onError) {
      options.onError(error, event);
    } else if (!warnedAboutFailure) {
      warnedAboutFailure = true;
      const reason = error instanceof Error ? error.message : String(error);
      console.warn(
        `Premier: dropped "${event.kind}" event (${reason}). Further delivery failures are silent; pass onError to observe them, required: true to throw, or read premierStats().dropped.`,
      );
    }
  } catch {
    // A broken error handler must not take the agent down either.
  }
}

/** The local collector refuses a request body larger than this (HTTP 413). */
export const MAX_EVENT_BYTES = 2 * 1024 * 1024;

// Room for the `premier_truncated` note added to a shortened payload.
const TRUNCATION_HEADROOM_BYTES = 4096;
// A shortened string keeps at least this many characters.
const TRUNCATION_KEEP_CHARS = 1024;
const TRUNCATION_MARKER = "...[truncated by the Premier SDK]";

function utf8Length(text: string): number {
  // A UTF-16 code unit is at most three UTF-8 bytes, so short text is not measured.
  if (text.length * 3 <= MAX_EVENT_BYTES) return text.length;
  return new TextEncoder().encode(text).length;
}

type StringLeaf = { holder: Record<string, unknown> | unknown[]; key: string | number; path: string };

function stringLeaves(value: unknown, path: string, leaves: StringLeaf[]): void {
  if (!value || typeof value !== "object") return;
  const holder = value as Record<string, unknown> | unknown[];
  const keys: (string | number)[] = Array.isArray(holder) ? holder.map((_, index) => index) : Object.keys(holder);
  for (const key of keys) {
    const child = (holder as Record<string | number, unknown>)[key];
    const childPath = path ? `${path}.${key}` : String(key);
    if (typeof child === "string") {
      leaves.push({ holder, key, path: childPath });
    } else {
      stringLeaves(child, childPath, leaves);
    }
  }
}

/**
 * Serialize `body`, shortening the longest payload strings when the result
 * would exceed the collector's body limit. A payload that cannot be brought
 * under the limit that way is replaced by a note recording its size, so the
 * event itself (kind, actor, status, causality) is still stored.
 */
function serializeWithinLimit(body: Record<string, unknown>, kind: string): string {
  const serialized = JSON.stringify(body);
  const originalBytes = utf8Length(serialized);
  if (originalBytes <= MAX_EVENT_BYTES) return serialized;

  const target = MAX_EVENT_BYTES - TRUNCATION_HEADROOM_BYTES;
  // Work on a copy: the caller's payload object is never modified.
  const copy = JSON.parse(serialized) as Record<string, unknown>;
  const note = { original_bytes: originalBytes, limit_bytes: MAX_EVENT_BYTES, fields: [] as string[] };
  let result = "";
  if (copy.payload && typeof copy.payload === "object") {
    const leaves: StringLeaf[] = [];
    stringLeaves(copy.payload, "", leaves);
    const read = (leaf: StringLeaf) => (leaf.holder as Record<string | number, string>)[leaf.key];
    leaves.sort((a, b) => read(b).length - read(a).length);
    // Every removed character is at least one byte of the serialized body.
    let excess = originalBytes - target;
    for (const leaf of leaves) {
      if (excess <= 0) break;
      const text = read(leaf);
      const removable = text.length - TRUNCATION_KEEP_CHARS;
      if (removable <= TRUNCATION_MARKER.length) break;
      const removed = Math.min(removable, excess + TRUNCATION_MARKER.length);
      let keep = text.length - removed;
      // Never split a surrogate pair.
      const last = text.charCodeAt(keep - 1);
      if (last >= 0xd800 && last <= 0xdbff) keep -= 1;
      (leaf.holder as Record<string | number, string>)[leaf.key] = text.slice(0, keep) + TRUNCATION_MARKER;
      excess -= removed - TRUNCATION_MARKER.length;
      if (note.fields.length < 20) note.fields.push(leaf.path);
    }
    if (excess <= 0 && !Array.isArray(copy.payload)) {
      (copy.payload as Record<string, unknown>).premier_truncated = note;
      result = JSON.stringify(copy);
    }
  }
  if (!result || utf8Length(result) > MAX_EVENT_BYTES) {
    copy.payload = { premier_truncated: { ...note, fields: [], payload: "dropped" } };
    result = JSON.stringify(copy);
  }
  stats.truncated += 1;
  if (!warnedAboutTruncation) {
    warnedAboutTruncation = true;
    try {
      console.warn(
        `Premier: "${kind}" event was ${originalBytes} bytes, over the collector's ${MAX_EVENT_BYTES}-byte limit; its payload was shortened (see payload.premier_truncated). Further truncations are silent.`,
      );
    } catch {
      // Reporting must not take the agent down.
    }
  }
  return result;
}

async function deliver(
  event: PremierEventInput,
  env: PremierEnv,
  options: PremierEmitOptions,
): Promise<PremierEvent> {
  const { traceId, collectorUrl, collectorToken } = premierEnv(env);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) {
    throw new Error("fetch is not available in this runtime");
  }

  const body: Record<string, unknown> = {
    trace_id: traceId,
    ...event,
    source: event.source ?? "premier-sdk",
    // The validator reports a missing or null payload as `payload_not_object`.
    payload: event.payload ?? {},
  };
  // Optional run metadata for a collector that keeps it. The local collector
  // started by `premier record` accepts the block and stores none of it, so
  // it is sent only when one of the variables is set.
  const run = Object.fromEntries(
    Object.entries({
      name: env.PREMIER_RUN_NAME,
      repository: env.PREMIER_REPOSITORY,
      branch: env.PREMIER_BRANCH,
      environment: env.PREMIER_ENVIRONMENT,
      started_at: env.PREMIER_STARTED_AT,
    }).filter(([, value]) => value !== undefined && value !== ""),
  );
  if (Object.keys(run).length > 0) body.run = run;
  // The local collector stores duration_ms as an unsigned integer, so
  // fractional timings (performance.now() deltas) must be normalized here
  // rather than rejected mid-run with a 400.
  if (typeof event.duration_ms === "number") {
    if (Number.isFinite(event.duration_ms)) {
      body.duration_ms = Math.min(
        Math.max(0, Math.round(event.duration_ms)),
        Number.MAX_SAFE_INTEGER,
      );
    } else {
      delete body.duration_ms;
    }
  }
  const serialized = serializeWithinLimit(body, event.kind);

  const timeoutMs = options.timeoutMs ?? DEFAULT_EMIT_TIMEOUT_MS;
  const controller = new AbortController();
  // Racing the abort (rather than relying on fetch to honour the signal) also
  // bounds custom fetch implementations and a stalled response body.
  const aborted = new Promise<never>((_resolve, reject) => {
    controller.signal.addEventListener("abort", () => reject(controller.signal.reason), {
      once: true,
    });
  });
  aborted.catch(() => {});
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
    timer = setTimeout(() => {
      controller.abort(new Error(`Premier collector did not respond within ${timeoutMs}ms`));
    }, timeoutMs);
  }
  const callerSignal = options.signal;
  const onCallerAbort = () => controller.abort(callerSignal?.reason);
  if (callerSignal?.aborted) {
    onCallerAbort();
  } else {
    callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
  }

  const request = async (): Promise<PremierEvent> => {
    const response = await fetchImpl(collectorUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${collectorToken}`,
        "Content-Type": "application/json",
      },
      body: serialized,
      signal: controller.signal,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(
        `Premier collector rejected event (${response.status}): ${text || response.statusText}`,
      );
    }

    return (await response.json()) as PremierEvent;
  };

  try {
    const pending = request();
    pending.catch(() => {});
    return await Promise.race([pending, aborted]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    callerSignal?.removeEventListener("abort", onCallerAbort);
  }
}

const inFlight = new Set<Promise<unknown>>();

/**
 * Emit a typed event to the Premier collector.
 *
 * Telemetry never crashes the host agent: this returns null when Premier is
 * not recording, and also when the collector is unreachable, slow, or rejects
 * the event (reported through `onError`, or one `console.warn`). Pass
 * `required: true` to throw in all of those cases instead.
 *
 * An emit that is not awaited is still delivered, unless the process calls
 * `process.exit()` first: `await flush()` before exiting.
 */
export function emit(
  event: PremierEventInput,
  options: PremierEmitOptions = {},
): Promise<PremierEvent | null> {
  const delivery = send(event, options);
  const tracked = delivery.then(
    () => {},
    () => {},
  );
  inFlight.add(tracked);
  void tracked.then(() => inFlight.delete(tracked));
  return delivery;
}

async function send(
  event: PremierEventInput,
  options: PremierEmitOptions,
): Promise<PremierEvent | null> {
  const env = options.env ?? process.env;
  if (!isPremierActive(env)) {
    if (options.required) {
      premierEnv(env);
    }
    return null;
  }
  try {
    const stored = await deliver(event, env, options);
    stats.delivered += 1;
    return stored;
  } catch (error) {
    if (options.required) {
      stats.dropped += 1;
      throw error;
    }
    reportFailure(error, event, options);
    return null;
  }
}

/**
 * Wait for every emit that has been started and not yet settled, including
 * ones started while waiting. Call it before `process.exit()`, which would
 * otherwise discard deliveries that were not awaited. Never rejects. With
 * `timeoutMs`, gives up after that long and resolves to `false`; resolves to
 * `true` when nothing is left in flight.
 */
export async function flush(options: { timeoutMs?: number } = {}): Promise<boolean> {
  const { timeoutMs } = options;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired =
    timeoutMs !== undefined && Number.isFinite(timeoutMs) && timeoutMs >= 0
      ? new Promise<"expired">((resolve) => {
          timer = setTimeout(() => resolve("expired"), timeoutMs);
        })
      : null;
  try {
    while (inFlight.size > 0) {
      const settled = Promise.allSettled([...inFlight]);
      if (expired) {
        if ((await Promise.race([settled, expired])) === "expired") return false;
      } else {
        await settled;
      }
    }
    return true;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

type PremierEventExtra = Partial<PremierEventInput>;
type HelperDefaults = { actor_type: string; status: string };

/**
 * What a helper accepts as its third argument: a partial event, or the event
 * this one follows (as returned by `emit` or a helper, `null` included), which
 * is the same as passing `childOf(event)`.
 */
export type PremierHelperExtra = PremierEventExtra | PremierEvent | null;

function isStoredEvent(value: unknown): value is PremierEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as PremierEvent).event_id === "string" &&
    "sequence" in value
  );
}

const CAUSALITY_FIELDS = [
  "parent_event_id",
  "span_id",
  "parent_span_id",
  "correlation_id",
  "links",
] as const;

/**
 * What the helpers remember about one recording so the completing half of a
 * pair can name its start: the open `agent.spawn` and `agent.delegation` of
 * each actor, the open `approval.request`s, and the `actor_type` each actor
 * was spawned with. Dropped when the collector or trace changes.
 */
type Recording = {
  key: string;
  open: Map<string, Promise<PremierEvent | null>>;
  approvals: Promise<PremierEvent | null>[];
  actorTypes: Map<string, string>;
};

let recording: Recording | undefined;

function recordingFor(env: PremierEnv): Recording {
  const key = `${env.PREMIER_COLLECTOR_URL ?? ""}\n${env.PREMIER_TRACE_ID ?? ""}`;
  if (!recording || recording.key !== key) {
    recording = { key, open: new Map(), approvals: [], actorTypes: new Map() };
  }
  return recording;
}

// The start each finishing kind closes, and whether both are by one actor.
const CLOSES: Record<string, { start: string; sameActor: boolean }> = {
  "agent.result": { start: "agent.spawn", sameActor: true },
  "agent.join": { start: "agent.delegation", sameActor: true },
  "approval.decision": { start: "approval.request", sameActor: false },
};

const settled = (pending: Promise<PremierEvent | null>): Promise<PremierEvent | null> =>
  pending.catch(() => null);

/**
 * Build one helper: its defaults first, then every *defined* field of `extra`,
 * then the positional kind/actor/payload. An `extra` carrying
 * `status: undefined` therefore keeps the default instead of erasing it.
 *
 * `agent.result`, `agent.join` and `approval.decision` name their start on
 * their own when `extra` carries no causality field: see `premier` below.
 */
function helper(kind: string, defaults: HelperDefaults) {
  return async (
    actor: string,
    payload: Record<string, unknown> = {},
    extra: PremierHelperExtra = {},
    options: PremierEmitOptions = {},
  ): Promise<PremierEvent | null> => {
    const given = isStoredEvent(extra) ? childOf(extra) : (extra ?? {});
    let defined = Object.fromEntries(
      Object.entries(given).filter(([, value]) => value !== undefined),
    ) as PremierEventExtra;
    const env = options.env ?? process.env;
    if (!isPremierActive(env)) {
      return emit({ ...defaults, ...defined, kind, actor_id: actor, payload }, options);
    }
    const state = recordingFor(env);

    const closes = CLOSES[kind];
    if (closes) {
      const openKey = `${closes.start}\n${actor}`;
      const explicit = CAUSALITY_FIELDS.some((field) => field in defined);
      let start: PremierEvent | null = null;
      if (closes.sameActor) {
        const pending = state.open.get(openKey);
        if (pending) {
          if (!explicit) start = await settled(pending);
          // Compare again: the actor may have been spawned anew meanwhile.
          if (state.open.get(openKey) === pending) state.open.delete(openKey);
        }
      } else if (explicit) {
        // The decision names its request: that request is no longer open.
        for (const pending of [...state.approvals]) {
          const request = await settled(pending);
          if (request && request.event_id === defined.parent_event_id) {
            state.approvals = state.approvals.filter((entry) => entry !== pending);
          }
        }
      } else if (state.approvals.length === 1) {
        // With several requests open the decision could belong to any of
        // them, so only a single open request is linked without being named.
        const [pending] = state.approvals;
        start = await settled(pending);
        state.approvals = state.approvals.filter((entry) => entry !== pending);
      }
      if (start) {
        // The finish is its start's child and stays in the start's span.
        defined = { ...defined, parent_event_id: start.event_id };
        if (start.span_id) defined.span_id = start.span_id;
        if (start.parent_span_id) defined.parent_span_id = start.parent_span_id;
        if (start.correlation_id) defined.correlation_id = start.correlation_id;
      }
    }

    // One actor keeps one actor_type: the one it was spawned with.
    const actorType = defined.actor_type ?? state.actorTypes.get(actor) ?? defaults.actor_type;
    if (kind === "agent.spawn") state.actorTypes.set(actor, actorType);

    const delivery = emit(
      { ...defaults, ...defined, actor_type: actorType, kind, actor_id: actor, payload },
      options,
    );
    if (kind === "agent.spawn" || kind === "agent.delegation") {
      state.open.set(`${kind}\n${actor}`, delivery);
    } else if (kind === "approval.request") {
      state.approvals.push(delivery);
      // Requests that were never stored cannot be linked to.
      void settled(delivery).then((stored) => {
        if (!stored) state.approvals = state.approvals.filter((entry) => entry !== delivery);
      });
    }
    return delivery;
  };
}

/**
 * Causality fields that make a new event a child of `parent` (an event
 * returned by `emit` or a helper). Safe to call with the `null` returned when
 * Premier is not recording. Pass the result as a helper's `extra`:
 *
 *   const spawned = await premier.spawn("researcher", {}, { span_id: "research" });
 *   await premier.tool("researcher", { tool: "rg" }, premier.childOf(spawned));
 */
export function childOf(
  parent: PremierEvent | null | undefined,
  extra: PremierEventExtra = {},
): PremierEventExtra {
  const causality: PremierEventExtra = {};
  if (parent) {
    causality.parent_event_id = parent.event_id;
    if (parent.span_id) causality.parent_span_id = parent.span_id;
    if (parent.correlation_id) causality.correlation_id = parent.correlation_id;
  }
  return { ...causality, ...extra };
}

/** A new unique id for `span_id` or `correlation_id`, such as `span-3f2a…`. */
export function newId(prefix = "span"): string {
  const random =
    typeof globalThis.crypto?.randomUUID === "function"
      ? globalThis.crypto.randomUUID()
      : `${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${random}`;
}

const delegation = helper("agent.delegation", { actor_type: "agent", status: "running" });
const spawn = helper("agent.spawn", { actor_type: "subagent", status: "running" });
const result = helper("agent.result", { actor_type: "subagent", status: "ok" });
const join = helper("agent.join", { actor_type: "agent", status: "ok" });
const message = helper("agent.message", { actor_type: "agent", status: "ok" });
const model = helper("model.response", { actor_type: "agent", status: "ok" });
const tool = helper("tool.execution", { actor_type: "agent", status: "ok" });
const approval = helper("approval.request", { actor_type: "agent", status: "pending" });
const approvalDecision = helper("approval.decision", { actor_type: "human", status: "approved" });

export type PremierSpanInit = {
  /** Written on every event of the span. Default `"agent"`. */
  actor_type?: string;
  /** Default: a generated id (`newId()`). */
  span_id?: string;
  /** The event, or the span, this span descends from. */
  parent?: PremierEvent | PremierSpan | null;
  /** Default: the parent's correlation id, when it has one. */
  correlation_id?: string;
};

type SpanHelper = (
  payload?: Record<string, unknown>,
  extra?: PremierHelperExtra,
  options?: PremierEmitOptions,
) => Promise<PremierEvent | null>;

/**
 * One actor's unit of work. Every event emitted through a span carries the
 * span's `actor_id`, `actor_type`, `span_id`, `parent_span_id`,
 * `parent_event_id` and `correlation_id`, so nothing is threaded by hand.
 */
export type PremierSpan = {
  readonly actor: string;
  readonly actor_type: string;
  readonly span_id: string;
  readonly parent_span_id: string | undefined;
  readonly parent_event_id: string | undefined;
  readonly correlation_id: string | undefined;
  /** The span's causality fields, with `extra` applied last. */
  fields(extra?: PremierEventExtra): PremierEventExtra;
  /** Emit any event as this span's actor. */
  emit(event: PremierEventInput, options?: PremierEmitOptions): Promise<PremierEvent | null>;
  /** A span of another (or the same) actor whose parent is this span. */
  child(actor: string, init?: Omit<PremierSpanInit, "parent">): PremierSpan;
  delegation: SpanHelper;
  spawn: SpanHelper;
  result: SpanHelper;
  join: SpanHelper;
  message: SpanHelper;
  model: SpanHelper;
  tool: SpanHelper;
  approval: SpanHelper;
};

function isSpan(value: unknown): value is PremierSpan {
  return typeof value === "object" && value !== null && typeof (value as PremierSpan).fields === "function";
}

/**
 * Open a span for `actor`:
 *
 *   const research = premier.span("researcher", { actor_type: "subagent" });
 *   await research.spawn({ task: "find the first divergence" });
 *   await research.tool({ tool: "rg" });
 *   await research.result({ outcome: "round before lock" });
 */
export function span(actor: string, init: PremierSpanInit = {}): PremierSpan {
  const parent = init.parent ?? null;
  const actorType = init.actor_type ?? "agent";
  const spanId = init.span_id ?? newId("span");
  const parentSpanId = (isSpan(parent) ? parent.span_id : parent?.span_id) || undefined;
  const parentEventId = (isSpan(parent) ? parent.parent_event_id : parent?.event_id) || undefined;
  const correlationId = init.correlation_id ?? (parent?.correlation_id || undefined);

  const fields = (extra: PremierEventExtra = {}): PremierEventExtra => {
    const own: PremierEventExtra = { actor_type: actorType, span_id: spanId };
    if (parentSpanId) own.parent_span_id = parentSpanId;
    if (parentEventId) own.parent_event_id = parentEventId;
    if (correlationId) own.correlation_id = correlationId;
    const defined = Object.fromEntries(
      Object.entries(extra).filter(([, value]) => value !== undefined),
    ) as PremierEventExtra;
    return { ...own, ...defined };
  };
  const bind =
    (target: ReturnType<typeof helper>): SpanHelper =>
    (payload = {}, extra = {}, options = {}) =>
      target(actor, payload, fields(isStoredEvent(extra) ? childOf(extra) : (extra ?? {})), options);

  const self: PremierSpan = {
    actor,
    actor_type: actorType,
    span_id: spanId,
    parent_span_id: parentSpanId,
    parent_event_id: parentEventId,
    correlation_id: correlationId,
    fields,
    emit: (event, options = {}) => emit({ ...fields(), actor_id: actor, ...event }, options),
    child: (childActor, childInit = {}) => span(childActor, { ...childInit, parent: self }),
    delegation: bind(delegation),
    spawn: bind(spawn),
    result: bind(result),
    join: bind(join),
    message: bind(message),
    model: bind(model),
    tool: bind(tool),
    approval: bind(approval),
  };
  return self;
}

/**
 * Convenience helpers for common agent evidence kinds. Each takes
 * `(actor, payload, extra, options)`: `extra` overrides the default
 * `actor_type` / `status` and carries causality fields (`span_id`,
 * `parent_span_id`, `parent_event_id`, `correlation_id`, `links`), or is the
 * event this one follows; `options` is the same object `emit` accepts.
 *
 * The completing half of a pair names its start without help: when `extra`
 * carries no causality field, `result` is linked to the same actor's open
 * `spawn`, `join` to the same actor's open `delegation`, and
 * `approvalDecision` to the open `approval` when exactly one is open.
 */
export const premier = {
  isActive: isPremierActive,
  emit,
  flush,
  childOf,
  span,
  newId,
  /** A coordinator hands work to other agents (`agent.delegation`); close with `join`. */
  delegation,
  /** An agent starts (`agent.spawn`); close with `result`. */
  spawn,
  /** An agent finishes (`agent.result`), completing its `spawn`. */
  result,
  /** A coordinator collects delegated agents (`agent.join`), completing `delegation`. */
  join,
  /** One agent tells another something (`agent.message`). */
  message,
  model,
  tool,
  /** An agent asks for permission (`approval.request`); close with `approvalDecision`. */
  approval,
  /** The decision on an `approval` (`approval.decision`); pass `extra.status: "denied"` to refuse. */
  approvalDecision,
};
