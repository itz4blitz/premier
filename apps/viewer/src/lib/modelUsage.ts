import { actorId } from './analysis';
import { directUsage, isRunSummary, nativeCost, nativeOf, nativeText, nativeUsage, payloadModel, payloadProvider, tokensOutsideInputAndOutput, usageReportedElsewhere } from './nativePayload';
import { eventPayload, type TraceEvent } from './types';

export type PromptRole = 'system' | 'developer' | 'user' | 'tool' | 'assistant';

export interface PromptEvidence {
  role: PromptRole;
  text: string;
  source: string;
  characters: number;
  tokens: number | null;
}

export interface TokenUsage {
  input: number | null;
  output: number | null;
  cacheRead: number | null;
  cacheWrite: number | null;
  reasoning: number | null;
  total: number | null;
}

export interface ModelCallUsage {
  event: TraceEvent;
  actor: string;
  provider: string | null;
  model: string;
  tokens: TokenUsage;
  costUsd: number | null;
  prompts: PromptEvidence[];
  response: string | null;
  toolSchemaCount: number;
}

export interface ModelUsageRollup {
  key: string;
  actor: string;
  provider: string | null;
  model: string;
  calls: number;
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  reasoning: number;
  total: number;
  costUsd: number;
  hasInput: boolean;
  hasOutput: boolean;
  hasCacheRead: boolean;
  hasCacheWrite: boolean;
  hasReasoning: boolean;
  hasTotal: boolean;
  hasCost: boolean;
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function finite(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, value);
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Math.max(0, Number(value));
  return null;
}

function numberFrom(sources: Array<Record<string, unknown> | null>, keys: string[]): number | null {
  for (const source of sources) {
    if (!source) continue;
    for (const key of keys) {
      const value = finite(source[key]);
      if (value !== null) return value;
    }
  }
  return null;
}

function stringFrom(source: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function textOf(value: unknown): string | null {
  if (typeof value === 'string') return value.trim() || null;
  if (Array.isArray(value)) {
    const joined = value.map((item) => {
      const itemRecord = record(item);
      return itemRecord ? textOf(itemRecord.text ?? itemRecord.content ?? itemRecord.input_text ?? itemRecord.output_text) : textOf(item);
    }).filter(Boolean).join('\n');
    return joined || null;
  }
  const valueRecord = record(value);
  if (!valueRecord) return null;
  return textOf(valueRecord.text ?? valueRecord.content ?? valueRecord.input_text ?? valueRecord.output_text);
}

function normalizedRole(value: unknown): PromptRole | null {
  const role = typeof value === 'string' ? value.toLowerCase() : '';
  if (role === 'system' || role === 'developer' || role === 'user' || role === 'tool' || role === 'assistant') return role;
  return null;
}

function roleTokenMap(payload: Record<string, unknown>, usage: Record<string, unknown> | null): Record<string, number> {
  const candidates = [usage?.input_tokens_by_role, usage?.prompt_tokens_by_role, payload.input_tokens_by_role, payload.prompt_tokens_by_role];
  for (const candidate of candidates) {
    const candidateRecord = record(candidate);
    if (!candidateRecord) continue;
    return Object.fromEntries(Object.entries(candidateRecord).flatMap(([key, value]) => {
      const numeric = finite(value);
      return numeric === null ? [] : [[key.toLowerCase(), numeric]];
    }));
  }
  return {};
}

function promptEvidence(payload: Record<string, unknown>, usage: Record<string, unknown> | null): { prompts: PromptEvidence[]; toolSchemaCount: number } {
  const roleTokens = roleTokenMap(payload, usage);
  const prompts: PromptEvidence[] = [];
  const seen = new Set<string>();
  const add = (role: PromptRole, value: unknown, source: string) => {
    const text = textOf(value);
    if (!text) return;
    const signature = `${role}\u0000${text}`;
    if (seen.has(signature)) return;
    seen.add(signature);
    prompts.push({ role, text, source, characters: text.length, tokens: roleTokens[role] ?? null });
  };

  for (const [role, keys] of Object.entries({
    system: ['system_prompt', 'system', 'system_instruction'],
    developer: ['developer_prompt', 'developer', 'instructions'],
    user: ['user_prompt', 'prompt'],
    assistant: ['assistant_prompt']
  }) as Array<[PromptRole, string[]]>) {
    for (const key of keys) if (payload[key] !== undefined) add(role, payload[key], key);
  }

  const messages = Array.isArray(payload.messages) ? payload.messages : Array.isArray(payload.input) ? payload.input : [];
  for (const [index, message] of messages.entries()) {
    const messageRecord = record(message);
    if (!messageRecord) {
      add('user', message, `input[${index}]`);
      continue;
    }
    const role = normalizedRole(messageRecord.role) ?? 'user';
    add(role, messageRecord.content ?? messageRecord.text ?? messageRecord.input_text, `messages[${index}]`);
  }

  const tools = Array.isArray(payload.tools) ? payload.tools : Array.isArray(payload.tool_definitions) ? payload.tool_definitions : [];
  for (const [index, tool] of tools.entries()) {
    const toolRecord = record(tool);
    const name = toolRecord && typeof toolRecord.name === 'string' ? toolRecord.name : `tool ${index + 1}`;
    add('tool', typeof tool === 'string' ? tool : `${name}\n${JSON.stringify(tool, null, 2)}`, `tools[${index}]`);
  }
  return { prompts, toolSchemaCount: tools.length };
}

function isModelKind(event: TraceEvent): boolean {
  return event.kind.startsWith('model.') || event.kind.startsWith('llm.');
}

/**
 * Usage for one event. Top-level `payload.usage` / `payload.model` win; adapter events fall back to the
 * provider object under `payload.native`. Anything no producer reported stays null (shown as unknown).
 */
function callUsage(event: TraceEvent, payload: Record<string, unknown>, summary: boolean): ModelCallUsage | null {
  // An adapter attaches one message's usage to the first event cut from it; later events of the same
  // message only name it, and the provider's repeated copy under `native` must not be counted again.
  if (usageReportedElsewhere(payload)) return null;
  const isModelEvent = isModelKind(event);
  const direct = directUsage(payload);
  // On an event that is not a model call, only usage attached to a single provider message is one call's usage.
  const native = nativeUsage(payload, !isModelEvent && !summary);
  const usage = direct ?? native;
  const hasDirectUsage = ['input_tokens', 'prompt_tokens', 'output_tokens', 'completion_tokens', 'total_tokens', 'tokens', 'cost_usd', 'total_cost_usd']
    .some((key) => finite(payload[key]) !== null);
  if (!isModelEvent && !usage && !hasDirectUsage) return null;
  // Normalized top-level usage carries totals; cache and reasoning detail may only exist in the provider object.
  const sources = [direct, payload, native];
  const inputDetails = record(usage?.input_tokens_details ?? usage?.prompt_tokens_details ?? payload.input_tokens_details);
  const outputDetails = record(usage?.output_tokens_details ?? usage?.completion_tokens_details ?? payload.output_tokens_details);

  const input = numberFrom(sources, ['input_tokens', 'prompt_tokens']);
  const output = numberFrom(sources, ['output_tokens', 'completion_tokens']);
  const cacheRead = numberFrom([inputDetails, ...sources], ['cached_tokens', 'cache_read_tokens', 'cache_read_input_tokens', 'cached_input_tokens']);
  const cacheWrite = numberFrom([inputDetails, ...sources], ['cache_creation_tokens', 'cache_write_tokens', 'cache_creation_input_tokens']);
  const reasoning = numberFrom([outputDetails, ...sources], ['reasoning_tokens', 'reasoning_output_tokens']);
  const explicitTotal = numberFrom(sources, ['total_tokens', 'tokens']);
  // Worked out from the parts, a total also counts what the provider reports beside them.
  const total = explicitTotal ?? (input !== null || output !== null ? (input ?? 0) + (output ?? 0) + tokensOutsideInputAndOutput(usage) : null);
  const { prompts, toolSchemaCount } = promptEvidence(payload, usage);
  return {
    event,
    actor: actorId(event),
    provider: payloadProvider(payload),
    model: payloadModel(payload) ?? 'Unknown model',
    tokens: { input, output, cacheRead, cacheWrite, reasoning, total },
    costUsd: numberFrom([direct, payload], ['cost_usd', 'total_cost_usd', 'cost']) ?? nativeCost(payload),
    prompts,
    response: textOf(payload.response ?? payload.output ?? payload.content ?? payload.text ?? payload.summary) ?? nativeText(payload),
    toolSchemaCount
  };
}

/** Last words of a kind that close a run, turn or agent: usage on such an event is a total. */
const AGGREGATE_ENDINGS = new Set(['result', 'summary', 'end', 'ended', 'complete', 'completed', 'finish', 'finished', 'done', 'total', 'usage']);

/**
 * An SDK or collector event that closes a run, turn or agent (`agent.result`, `session.end`) and
 * carries usage at its top level: the sum of calls that are normally recorded one by one too.
 */
function isAggregateEvent(event: TraceEvent, payload: Record<string, unknown>): boolean {
  if (isModelKind(event) || event.kind.startsWith('tool.') || event.kind.startsWith('mcp.') || nativeOf(payload)) return false;
  return AGGREGATE_ENDINGS.has(event.kind.trim().toLowerCase().split(/[^a-z0-9]+/).pop() ?? '');
}

/** A provider's end-of-run total on an event that is not itself a model call. */
function isSummaryEvent(event: TraceEvent, payload: Record<string, unknown>): boolean {
  return !isModelKind(event) && isRunSummary(payload);
}

/** Last words of a model kind that open a call which a later event answers. */
const REQUEST_ENDINGS = new Set(['request', 'requested', 'start', 'started', 'call', 'prompt', 'input']);

function isRequestKind(event: TraceEvent): boolean {
  return isModelKind(event) && REQUEST_ENDINGS.has(event.kind.trim().toLowerCase().split(/[^a-z0-9]+/).pop() ?? '');
}

/**
 * The model event that answers a request: the next one that is not itself a request and names the
 * request as its parent, shares its span, or shares its correlation id and actor.
 */
function answers(request: TraceEvent, candidate: TraceEvent): boolean {
  if (!isModelKind(candidate) || isRequestKind(candidate) || candidate.sequence <= request.sequence) return false;
  return candidate.parent_event_id === request.event_id
    || (request.span_id !== '' && candidate.span_id === request.span_id)
    || (request.correlation_id !== '' && candidate.correlation_id === request.correlation_id && actorId(candidate) === actorId(request));
}

/** One call recorded as a request and a response: the response's row, completed from the request. */
function mergeRequest(response: ModelCallUsage, request: ModelCallUsage): ModelCallUsage {
  const tokens = { ...response.tokens };
  // Whichever event the provider's usage was attached to, it is counted once.
  if (Object.values(tokens).every((value) => value === null)) Object.assign(tokens, request.tokens);
  return {
    ...response,
    provider: response.provider ?? request.provider,
    model: response.model === 'Unknown model' ? request.model : response.model,
    tokens,
    costUsd: response.costUsd ?? request.costUsd,
    prompts: response.prompts.length ? response.prompts : request.prompts,
    toolSchemaCount: response.toolSchemaCount || request.toolSchemaCount
  };
}

export function modelCallUsage(event: TraceEvent): ModelCallUsage | null {
  const payload = eventPayload(event);
  // Run summaries repeat the per-call usage; modelUsage() decides whether one is needed.
  if (isSummaryEvent(event, payload) || isAggregateEvent(event, payload)) return null;
  return callUsage(event, payload, false);
}

/**
 * The model calls of a run, each counted once:
 *
 * - a call recorded as a request event and a response event is one call, with one set of tokens;
 * - a provider's or SDK's end-of-run total is used only when no call reported usage of its own.
 */
export function modelUsage(events: TraceEvent[]): { calls: ModelCallUsage[]; rollups: ModelUsageRollup[] } {
  const perCall = new Map<string, ModelCallUsage>();
  const summaries = new Map<string, ModelCallUsage>();
  const aggregates = new Map<string, ModelCallUsage>();
  for (const event of events) {
    const payload = eventPayload(event);
    const summary = isSummaryEvent(event, payload);
    const call = callUsage(event, payload, summary);
    if (!call) continue;
    if (summary) summaries.set(event.event_id, call);
    else if (isAggregateEvent(event, payload)) aggregates.set(event.event_id, call);
    else perCall.set(event.event_id, call);
  }
  // Fold each answered request into its response.
  const modelEvents = events.filter((event) => perCall.has(event.event_id) && isModelKind(event));
  const answered = new Set<string>();
  for (const [index, request] of modelEvents.entries()) {
    if (!isRequestKind(request)) continue;
    const response = modelEvents.slice(index + 1).find((candidate) => !answered.has(candidate.event_id) && answers(request, candidate));
    if (!response) continue;
    answered.add(response.event_id);
    perCall.set(response.event_id, mergeRequest(perCall.get(response.event_id)!, perCall.get(request.event_id)!));
    perCall.delete(request.event_id);
  }
  // A run summary is the only usage evidence when the provider reported nothing per call.
  const reported = [...perCall.values()].filter((call) => call.tokens.total !== null);
  const actorsWithUsage = new Set(reported.map((call) => call.actor));
  const calls = events.flatMap((event) => {
    const call = perCall.get(event.event_id);
    if (call) return [call];
    const summary = summaries.get(event.event_id);
    if (summary) return !actorsWithUsage.has(summary.actor) && (summary.tokens.total !== null || summary.costUsd !== null) ? [summary] : [];
    // An SDK total may cover every actor's calls, so any per-call usage at all replaces it.
    const aggregate = aggregates.get(event.event_id);
    return aggregate && reported.length === 0 && (aggregate.tokens.total !== null || aggregate.costUsd !== null) ? [aggregate] : [];
  });
  const groups = new Map<string, ModelUsageRollup>();
  for (const call of calls) {
    const key = `${call.provider ?? ''}\u0000${call.model}\u0000${call.actor}`;
    const current = groups.get(key) ?? {
      key, actor: call.actor, provider: call.provider, model: call.model, calls: 0,
      input: 0, output: 0, cacheRead: 0, cacheWrite: 0, reasoning: 0, total: 0, costUsd: 0,
      hasInput: false, hasOutput: false, hasCacheRead: false, hasCacheWrite: false, hasReasoning: false, hasTotal: false, hasCost: false
    };
    current.calls += 1;
    for (const key of ['input', 'output', 'cacheRead', 'cacheWrite', 'reasoning', 'total'] as const) {
      const value = call.tokens[key];
      if (value !== null) {
        current[key] += value;
        current[`has${key[0].toUpperCase()}${key.slice(1)}` as 'hasInput'] = true;
      }
    }
    if (call.costUsd !== null) { current.costUsd += call.costUsd; current.hasCost = true; }
    groups.set(key, current);
  }
  return { calls, rollups: [...groups.values()].sort((a, b) => b.total - a.total || b.calls - a.calls) };
}
