/**
 * Premier first-party emitter SDK.
 *
 * Under `premier record -- <command>`, the CLI injects:
 *   PREMIER_TRACE_ID, PREMIER_COLLECTOR_URL, PREMIER_COLLECTOR_TOKEN
 *
 * Call `emit(...)` from agent runtimes to attach typed multi-actor evidence.
 */

export type PremierEventInput = {
  kind: string;
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
 * event (including `payload_json`); Premier Cloud batch ingestion returns only
 * the required fields.
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
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return Boolean(env.PREMIER_COLLECTOR_URL && env.PREMIER_COLLECTOR_TOKEN);
}

export function premierEnv(env: NodeJS.ProcessEnv = process.env): {
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
  env?: NodeJS.ProcessEnv;
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

function reportFailure(
  error: unknown,
  event: PremierEventInput,
  options: PremierEmitOptions,
): void {
  try {
    if (options.onError) {
      options.onError(error, event);
    } else if (!warnedAboutFailure) {
      warnedAboutFailure = true;
      const reason = error instanceof Error ? error.message : String(error);
      console.warn(
        `Premier: dropped "${event.kind}" event (${reason}). Further delivery failures are silent; pass onError to observe them or required: true to throw.`,
      );
    }
  } catch {
    // A broken error handler must not take the agent down either.
  }
}

async function deliver(
  event: PremierEventInput,
  env: NodeJS.ProcessEnv,
  options: PremierEmitOptions,
): Promise<PremierEvent> {
  const { traceId, collectorUrl, collectorToken } = premierEnv(env);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) {
    throw new Error("fetch is not available in this runtime");
  }

  const body: Record<string, unknown> = {
    trace_id: traceId,
    run: {
      name: env.PREMIER_RUN_NAME,
      repository: env.PREMIER_REPOSITORY,
      branch: env.PREMIER_BRANCH,
      environment: env.PREMIER_ENVIRONMENT,
      started_at: env.PREMIER_STARTED_AT,
    },
    ...event,
    source: event.source ?? "premier-sdk",
  };
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
  const serialized = JSON.stringify(body);

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

/**
 * Emit a typed event to the Premier collector.
 *
 * Telemetry never crashes the host agent: this returns null when Premier is
 * not recording, and also when the collector is unreachable, slow, or rejects
 * the event (reported through `onError`, or one `console.warn`). Pass
 * `required: true` to throw in all of those cases instead.
 */
export async function emit(
  event: PremierEventInput,
  options: PremierEmitOptions = {},
): Promise<PremierEvent | null> {
  const env = options.env ?? process.env;
  if (!isPremierActive(env)) {
    if (options.required) {
      premierEnv(env);
    }
    return null;
  }
  try {
    return await deliver(event, env, options);
  } catch (error) {
    if (options.required) {
      throw error;
    }
    reportFailure(error, event, options);
    return null;
  }
}

type PremierEventExtra = Partial<PremierEventInput>;
type HelperDefaults = { actor_type: string; status: string };

/**
 * Build one helper: its defaults first, then every *defined* field of `extra`,
 * then the positional kind/actor/payload. An `extra` carrying
 * `status: undefined` therefore keeps the default instead of erasing it.
 */
function helper(kind: string, defaults: HelperDefaults) {
  return (
    actor: string,
    payload: Record<string, unknown> = {},
    extra: PremierEventExtra = {},
    options: PremierEmitOptions = {},
  ): Promise<PremierEvent | null> => {
    const defined = Object.fromEntries(
      Object.entries(extra).filter(([, value]) => value !== undefined),
    ) as PremierEventExtra;
    return emit({ ...defaults, ...defined, kind, actor_id: actor, payload }, options);
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

/**
 * Convenience helpers for common agent evidence kinds. Each takes
 * `(actor, payload, extra, options)`: `extra` overrides the default
 * `actor_type` / `status` and carries causality fields (`span_id`,
 * `parent_span_id`, `parent_event_id`, `correlation_id`, `links`); `options`
 * is the same object `emit` accepts.
 */
export const premier = {
  isActive: isPremierActive,
  emit,
  childOf,
  /** A coordinator hands work to other agents (`agent.delegation`); close with `join`. */
  delegation: helper("agent.delegation", { actor_type: "agent", status: "running" }),
  /** An agent starts (`agent.spawn`); close with `result`. */
  spawn: helper("agent.spawn", { actor_type: "subagent", status: "running" }),
  /** An agent finishes (`agent.result`), completing its `spawn`. */
  result: helper("agent.result", { actor_type: "subagent", status: "ok" }),
  /** A coordinator collects delegated agents (`agent.join`), completing `delegation`. */
  join: helper("agent.join", { actor_type: "agent", status: "ok" }),
  /** One agent tells another something (`agent.message`). */
  message: helper("agent.message", { actor_type: "agent", status: "ok" }),
  model: helper("model.response", { actor_type: "agent", status: "ok" }),
  tool: helper("tool.execution", { actor_type: "agent", status: "ok" }),
  /** An agent asks for permission (`approval.request`); close with `approvalDecision`. */
  approval: helper("approval.request", { actor_type: "agent", status: "pending" }),
  /** The decision on an `approval` (`approval.decision`); pass `extra.status: "denied"` to refuse. */
  approvalDecision: helper("approval.decision", { actor_type: "human", status: "approved" }),
};
