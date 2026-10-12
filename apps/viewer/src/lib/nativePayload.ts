/**
 * Readers for the fields the viewer needs from an event payload, wherever a producer put them.
 *
 * SDK and demo events carry `model`, `usage`, `tool`, and `error` at the top level. Events captured by a
 * native adapter carry the provider's own object under `payload.native`; newer recorders also copy the
 * common fields to the top level. Every reader here prefers the top level and only then looks at the
 * well-known places inside `native`, so both generations of trace read the same way.
 *
 * Nothing is invented: a field that no producer recorded comes back as `null`, never as 0 or ''.
 */

type Fields = Record<string, unknown>;

export function record(value: unknown): Fields | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Fields : null;
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function finite(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, value);
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Math.max(0, Number(value));
  return null;
}

function firstText(source: Fields | null, keys: string[]): string | null {
  if (!source) return null;
  for (const key of keys) {
    const value = text(source[key]);
    if (value) return value;
  }
  return null;
}

/** The provider's own event object, when this payload is an adapter envelope. */
export function nativeOf(payload: Fields): Fields | null {
  return record(payload.native);
}

/** Adapter label such as `init` or `item.completed`, for rows with nothing better to say. */
export function nativeType(payload: Fields): string | null {
  const native = nativeOf(payload);
  if (!native) return null;
  const type = text(payload.native_type);
  const subtype = text(native.subtype);
  if (type && type !== 'unknown') return subtype ? `${type} ${subtype}` : type;
  return subtype ?? text(native.role);
}

/** Content blocks of a chat-style message (Anthropic/OpenAI shapes). */
function contentBlocks(native: Fields): Fields[] {
  const message = record(native.message);
  const item = record(native.item);
  for (const candidate of [message?.content, native.content, item?.content]) {
    if (Array.isArray(candidate)) return candidate.map(record).filter((block): block is Fields => block !== null);
  }
  return [];
}

function flattenText(value: unknown): string | null {
  if (typeof value === 'string') return text(value);
  if (Array.isArray(value)) {
    const joined = value.map((item) => {
      const block = record(item);
      return block ? flattenText(block.text ?? block.content ?? block.output_text ?? block.input_text) : flattenText(item);
    }).filter(Boolean).join('\n');
    return joined || null;
  }
  const block = record(value);
  return block ? flattenText(block.text ?? block.content ?? block.output_text ?? block.input_text) : null;
}

/** Model identifier: `payload.model`, then the provider message/response that names it. */
export function payloadModel(payload: Fields): string | null {
  const direct = firstText(payload, ['model', 'model_id', 'deployment']);
  if (direct) return direct;
  const native = nativeOf(payload);
  if (!native) return null;
  for (const source of [native, record(native.message), record(native.response), record(native.item), record(native.part)]) {
    const model = firstText(source, ['model', 'model_id', 'modelID', 'model_name']);
    if (model) return model;
  }
  // Claude Code's final result keys cumulative usage by model id.
  const byModel = Object.keys(record(native.modelUsage) ?? {});
  return byModel.length === 1 ? byModel[0] : null;
}

export function payloadProvider(payload: Fields): string | null {
  return firstText(payload, ['provider', 'vendor']);
}

/** opencode reports `{ input, output, reasoning, cache: { read, write } }`; rename to the common keys. */
function commonUsageKeys(usage: Fields): Fields {
  if (usage.input_tokens !== undefined || usage.prompt_tokens !== undefined || usage.output_tokens !== undefined
    || usage.completion_tokens !== undefined || usage.total_tokens !== undefined) return usage;
  const cache = record(usage.cache);
  const renamed: Fields = { ...usage };
  if (finite(usage.input) !== null) renamed.input_tokens = usage.input;
  if (finite(usage.output) !== null) renamed.output_tokens = usage.output;
  if (finite(usage.reasoning) !== null) renamed.reasoning_tokens = usage.reasoning;
  if (finite(usage.total) !== null) renamed.total_tokens = usage.total;
  if (finite(cache?.read) !== null) renamed.cache_read_tokens = cache?.read;
  if (finite(cache?.write) !== null) renamed.cache_write_tokens = cache?.write;
  return renamed;
}

/**
 * A provider's end-of-run summary (Claude Code / Gemini `result`): its usage is the cumulative total of
 * calls that were usually also recorded one by one, so it must not be added to them.
 */
export function isRunSummary(payload: Fields): boolean {
  const native = nativeOf(payload);
  if (!native) return false;
  return native.type === 'result' || native.num_turns !== undefined || record(native.modelUsage) !== null || record(native.stats) !== null;
}

/**
 * Usage block inside the provider object. `perCallOnly` restricts the search to usage attached to one
 * model message, which is the only kind that is safe to count on an event that is not itself a model call.
 */
export function nativeUsage(payload: Fields, perCallOnly = false): Fields | null {
  const native = nativeOf(payload);
  if (!native) return null;
  const message = record(native.message);
  const perCall = record(message?.usage);
  if (perCall) return commonUsageKeys(perCall);
  if (perCallOnly) return null;
  const response = record(native.response);
  const item = record(native.item);
  const info = record(native.info);
  const part = record(native.part);
  for (const candidate of [
    native.usage, response?.usage, item?.usage, info?.last_token_usage, info?.total_token_usage,
    part?.tokens, native.tokens, native.stats
  ]) {
    const usage = record(candidate);
    if (usage) return commonUsageKeys(usage);
  }
  return null;
}

/** Usage block for this event: `payload.usage`, then the provider object. */
export function payloadUsage(payload: Fields, perCallOnly = false): Fields | null {
  return record(payload.usage) ?? nativeUsage(payload, perCallOnly);
}

/** Recorded cost in USD from the provider object, or null when the provider did not report one. */
export function nativeCost(payload: Fields): number | null {
  const native = nativeOf(payload);
  if (!native) return null;
  for (const source of [native, record(native.part), record(native.usage), record(native.message)]) {
    if (!source) continue;
    for (const key of ['total_cost_usd', 'cost_usd', 'cost']) {
      const value = finite(source[key]);
      if (value !== null) return value;
    }
  }
  return null;
}

/** Total tokens for a row label, or null when no producer reported usage. */
export function payloadTotalTokens(payload: Fields): number | null {
  const direct = finite(payload.tokens) ?? finite(payload.total_tokens);
  if (direct !== null) return direct;
  const usage = payloadUsage(payload);
  if (!usage) return null;
  const total = finite(usage.total_tokens) ?? finite(usage.tokens);
  if (total !== null) return total;
  const input = finite(usage.input_tokens) ?? finite(usage.prompt_tokens);
  const output = finite(usage.output_tokens) ?? finite(usage.completion_tokens);
  return input === null && output === null ? null : (input ?? 0) + (output ?? 0);
}

function toolFromNative(native: Fields): string | null {
  const direct = firstText(native, ['tool_name', 'tool', 'name']);
  if (direct) return direct;
  const item = record(native.item);
  // Codex: command executions are identified by their command line, MCP/function calls by tool name.
  const fromItem = firstText(item, ['tool', 'name', 'command']);
  if (fromItem) return fromItem;
  const fromPart = firstText(record(native.part), ['tool', 'name']);
  if (fromPart) return fromPart;
  const toolUse = contentBlocks(native).find((block) => block.type === 'tool_use' || block.type === 'function_call');
  if (toolUse && text(toolUse.name)) return text(toolUse.name);
  const calls = Array.isArray(native.tool_calls) ? native.tool_calls : Array.isArray(record(native.message)?.tool_calls) ? record(native.message)!.tool_calls as unknown[] : [];
  for (const call of [...calls, native.tool_call, native.function, native.params]) {
    const callRecord = record(call);
    const name = firstText(record(callRecord?.function), ['name']) ?? firstText(callRecord, ['name', 'tool']);
    if (name) return name;
  }
  return text(native.command);
}

/** Tool identity: `payload.tool` / `payload.name`, then the provider's tool call. */
export function payloadTool(payload: Fields): string | null {
  const direct = firstText(payload, ['tool', 'tool_name', 'name']);
  if (direct) return direct;
  const native = nativeOf(payload);
  return native ? toolFromNative(native) : firstText(payload, ['command']);
}

/** Exit status of a native command execution (Codex `item.exit_code`), when one was recorded. */
export function nativeExitCode(payload: Fields): number | null {
  const native = nativeOf(payload);
  if (!native) return null;
  const code = native.exit_code ?? record(native.item)?.exit_code;
  return typeof code === 'number' && Number.isFinite(code) ? code : null;
}

function errorText(value: unknown): string | null {
  if (typeof value === 'string') return text(value);
  const fields = record(value);
  if (!fields) return null;
  return firstText(fields, ['message', 'error', 'detail', 'reason', 'type', 'code']) ?? JSON.stringify(fields);
}

/** What went wrong, from `payload.error` / `payload.failed` or the provider's error markers. */
export function payloadError(payload: Fields): string | null {
  for (const key of ['error', 'failed']) {
    const value = payload[key];
    if (value === undefined || value === null || value === false || value === '') continue;
    return errorText(value) ?? String(value);
  }
  const native = nativeOf(payload);
  if (!native) return null;
  const item = record(native.item);
  const explicit = errorText(native.error) ?? errorText(item?.error);
  if (explicit) return explicit;
  if (native.is_error === true) {
    return flattenText(native.result) ?? flattenText(native.content) ?? flattenText(native.message) ?? 'reported an error';
  }
  const failedBlock = contentBlocks(native).find((block) => block.is_error === true);
  if (failedBlock) return flattenText(failedBlock.content) ?? flattenText(failedBlock.text) ?? 'tool reported an error';
  if (text(native.type)?.toLowerCase() === 'error') return flattenText(native.message) ?? flattenText(native.content) ?? 'provider error';
  const exit = nativeExitCode(payload);
  if (exit !== null && exit !== 0) {
    const output = flattenText(item?.aggregated_output) ?? flattenText(item?.stderr) ?? flattenText(native.stderr);
    return output ? `exit ${exit}: ${output}` : `exit ${exit}`;
  }
  const status = (text(native.status) ?? text(item?.status))?.toLowerCase();
  if (status && ['error', 'failed', 'denied'].includes(status)) {
    return flattenText(native.message) ?? flattenText(native.reason) ?? flattenText(item?.message) ?? status;
  }
  return null;
}

/**
 * Objects in which a provider states the outcome of the event itself: the line, its `item` or `part`,
 * and their `state`. Arguments, output and prose are never consulted.
 */
function outcomeScopes(native: Fields): Fields[] {
  const scopes = [native, record(native.item), record(native.part)].filter((scope): scope is Fields => scope !== null);
  return [...scopes, ...scopes.map((scope) => record(scope.state)).filter((scope): scope is Fields => scope !== null)];
}

function flagsError(scope: Fields): boolean {
  return scope.is_error === true || scope.isError === true;
}

function statesFailure(scope: Fields): boolean {
  if (flagsError(scope)) return true;
  const status = [scope.status, scope.state].find((value) => typeof value === 'string') as string | undefined;
  if (status && ['error', 'errored', 'failed', 'failure', 'denied', 'rejected'].includes(status.trim().toLowerCase())) return true;
  const exit = [scope.exit_code, scope.exitCode].find((value) => value !== undefined && value !== null);
  if (typeof exit === 'number' && exit !== 0) return true;
  const error = scope.error;
  if (error === undefined || error === null || error === false || error === 0 || error === '') return false;
  if (Array.isArray(error)) return error.length > 0;
  return typeof error === 'object' ? Object.keys(error).length > 0 : true;
}

/**
 * True when the provider object states outright that the event failed: `is_error`, an error
 * status or state, a non-zero exit code, or an error value. Current adapters also record that as the
 * event status; older traces carry it only here. Keep aligned with `issues.rs` in premier-cli.
 *
 * A chat-style line can carry several tool results. An event that names one of them by
 * `correlationId` answers only for that block; otherwise the event stands for the whole line.
 */
export function nativeFailure(payload: Fields, correlationId = ''): boolean {
  const native = nativeOf(payload);
  if (!native) return false;
  if (outcomeScopes(native).some(statesFailure)) return true;
  if (typeof native.type === 'string' && native.type.trim().toLowerCase() === 'error') return true;
  const blocks = contentBlocks(native);
  const own = correlationId
    ? blocks.filter((block) => ['tool_use_id', 'tool_call_id', 'call_id', 'id'].some((key) => block[key] === correlationId))
    : [];
  return (own.length ? own : blocks).some(flagsError);
}

/** Human-readable content of the provider event: the assistant text, tool output, or final result. */
export function nativeText(payload: Fields): string | null {
  const native = nativeOf(payload);
  if (!native) return null;
  const item = record(native.item);
  const part = record(native.part);
  const blocks = contentBlocks(native);
  const fromBlocks = blocks
    .map((block) => block.type === 'tool_result' ? flattenText(block.content) : flattenText(block.text))
    .filter(Boolean).join('\n');
  return flattenText(native.result)
    ?? flattenText(native.text)
    ?? (fromBlocks || null)
    ?? flattenText(native.content)
    ?? flattenText(native.message)
    ?? flattenText(item?.text)
    ?? flattenText(item?.aggregated_output)
    ?? flattenText(part?.text)
    ?? flattenText(native.delta)
    ?? flattenText(native.output);
}
