import { nativeExitCode, nativeFailure, payloadFailure, nativeOf, nativeText, nativeType, payloadError, payloadModel, payloadTool, payloadTotalTokens, record } from './nativePayload';
import { parentResolver } from './causal';
import { isAbandoned, type EventCategory, type EventFamily, type EventFilters, type TraceEvent, type TraceManifest } from './types';

export type ActorRole = 'process' | 'agent' | 'subagent' | 'human' | 'system';

export interface AgentSummary {
  id: string;
  type: ActorRole;
  events: number;
  errors: number;
  firstSequence: number;
  status: string;
}

export interface ActorInventory {
  processes: number;
  agents: number;
  subagents: number;
  humans: number;
  systems: number;
}

export interface RunHealth {
  label: 'Running' | 'Abandoned' | 'Locked' | 'Unsupported' | 'Awaiting approval' | 'Blocked' | 'Needs attention' | 'Interrupted' | 'Failed' | 'Passed' | 'Unknown' | 'Unverified';
  tone: 'running' | 'warning' | 'error' | 'success';
  detail: string;
}

export interface TimelineEvent extends TraceEvent {
  lane: number;
  parentLane: number | null;
  depth: number;
  elapsedMs: number;
}

export function actorId(event: TraceEvent): string {
  return event.actor_id || 'root';
}

export function actorRole(event: TraceEvent): ActorRole {
  const type = event.actor_type?.trim().toLowerCase();
  if (type === 'process' || type === 'human' || type === 'subagent' || type === 'system') return type;
  if (type === 'agent') return actorId(event) === 'root' && event.kind.startsWith('process.') ? 'process' : 'agent';
  if (event.kind.startsWith('process.')) return 'process';
  return actorId(event) === 'root' ? 'process' : 'agent';
}

/** Statuses that make an event an issue. `rejected` is a refusal, like `denied`. */
const ISSUE_STATUSES = new Set(['error', 'failed', 'denied', 'blocked', 'rejected']);
/** Statuses that refuse an operation: the run was stopped by a decision, not by a fault. */
export const REFUSAL_STATUSES = new Set(['denied', 'blocked', 'rejected']);
/** Whole words of a kind that name a failure. `tool.failover` and `process.stderr` have none. */
const FAILURE_SEGMENTS = new Set(['error', 'errors', 'errored', 'fail', 'failed', 'failure']);
/** Payload keys that can state a failure; an event without any of them is never decoded. */
const FAILURE_KEYS = /"(?:is_error|isError|error|exit_code|exitCode|status|state)"/;

/**
 * The one authoritative issue predicate for the viewer. An event is an issue when
 *
 * 1. its status is `error`, `failed`, `denied`, `blocked` or `rejected`; or
 * 2. a whole segment of its kind (split at every character that is not a letter or digit) is
 *    `error`, `errors`, `errored`, `fail`, `failed` or `failure`; or
 * 3. the provider object under `payload.native` states a failure; or
 * 4. it has no status at all and its payload states a failure at the top level (`is_error`, a
 *    non-empty `error`, a non-zero `exit_code`, or a failing `status`). A status the producer did
 *    record is its own statement of the outcome and is not second-guessed.
 *
 * `crates/premier-cli/src/issues.rs` is the server's copy; both run the cases in
 * `crates/premier-cli/tests/fixtures/issues/issue-cases.json`. Change one and the other must follow.
 */
export function isIssue(event: TraceEvent): boolean {
  return issueBasis(event) !== null;
}

/** Which of the rules above makes an event an issue: what it says outright, or only its payload. */
export function issueBasis(event: TraceEvent): 'status' | 'kind' | 'payload' | null {
  const status = event.status.trim().toLowerCase();
  if (ISSUE_STATUSES.has(status)) return 'status';
  if (event.kind.trim().toLowerCase().split(/[^a-z0-9]+/).some((segment) => FAILURE_SEGMENTS.has(segment))) return 'kind';
  return statesPayloadFailure(event, status === '') ? 'payload' : null;
}

const payloadFailures = new WeakMap<TraceEvent, boolean>();

/**
 * A failure stated only in the payload: by the provider object of an adapter event, or at the top
 * level of an event recorded without a status. The predicate runs for every row and count, so the
 * decoded answer is kept per event.
 */
function statesPayloadFailure(event: TraceEvent, unstated: boolean): boolean {
  // Most events carry neither; skip decoding their payload.
  const envelope = event.payload_json.includes('"native"');
  if (!envelope && !(unstated && FAILURE_KEYS.test(event.payload_json))) return false;
  const known = payloadFailures.get(event);
  if (known !== undefined) return known;
  let failed = false;
  try {
    const payload = record(JSON.parse(event.payload_json));
    failed = payload !== null && (nativeFailure(payload, event.correlation_id) || (unstated && payloadFailure(payload)));
  } catch {
    failed = false;
  }
  payloadFailures.set(event, failed);
  return failed;
}

/** The status of an event that answers an approval request. */
const DECIDED_STATUSES = new Set(['approved', 'denied', 'rejected']);

/**
 * Pending events nobody has answered yet. A request is settled by a later `approval.decision`, or by
 * any later approved/denied/rejected event, that shares its correlation id or span, or that names the
 * request as its parent event.
 */
export function awaitingApprovals(events: TraceEvent[]): TraceEvent[] {
  const decidedCorrelations = new Set<string>();
  const decidedSpans = new Set<string>();
  const decidedParents = new Set<string>();
  const awaiting: TraceEvent[] = [];
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    const status = event.status.trim().toLowerCase();
    if (status === 'pending') {
      const settled = (event.correlation_id !== '' && decidedCorrelations.has(event.correlation_id))
        || (event.span_id !== '' && decidedSpans.has(event.span_id))
        || decidedParents.has(event.event_id);
      if (!settled) awaiting.push(event);
      continue;
    }
    if (DECIDED_STATUSES.has(status) || event.kind.trim().toLowerCase() === 'approval.decision') {
      if (event.correlation_id) decidedCorrelations.add(event.correlation_id);
      if (event.span_id) decidedSpans.add(event.span_id);
      if (event.parent_event_id) decidedParents.add(event.parent_event_id);
    }
  }
  return awaiting.reverse();
}

/**
 * Which filter tab a kind belongs to, by the text before its first dot, compared without regard to
 * case. Documented in docs/events.md ("Viewer categories"); keep the two in step.
 */
const KIND_FAMILIES: Record<string, EventFamily> = {
  agent: 'agent',
  model: 'model',
  llm: 'model',
  tool: 'tool',
  mcp: 'tool',
  approval: 'approval',
  process: 'process',
  // The recorder's own bookkeeping about the run and its adapter.
  session: 'process',
  adapter: 'process'
};

/** The recorded family stays stable even when an event is also an issue. Unknown kinds are `other`. */
export function familyOf(event: TraceEvent): EventFamily {
  const prefix = event.kind.trim().split('.')[0].toLowerCase();
  // Own keys only: a kind such as `constructor.x` must not find something on the prototype.
  return Object.prototype.hasOwnProperty.call(KIND_FAMILIES, prefix) ? KIND_FAMILIES[prefix] : 'other';
}

export function categoryOf(event: TraceEvent): EventCategory {
  return isIssue(event) ? 'error' : familyOf(event);
}

export function summarizeAgents(events: TraceEvent[]): AgentSummary[] {
  const actors = new Map<string, AgentSummary>();
  const awaiting = new Set(awaitingApprovals(events));
  for (const event of events) {
    const id = actorId(event);
    const current = actors.get(id) ?? {
      id,
      type: actorRole(event),
      events: 0,
      errors: 0,
      firstSequence: event.sequence,
      status: 'ok'
    };
    current.events += 1;
    if (isIssue(event)) {
      current.errors += 1;
      current.status = 'error';
    } else if ((event.status === 'running' || awaiting.has(event)) && current.status !== 'error') {
      current.status = event.status;
    }
    actors.set(id, current);
  }
  return [...actors.values()].sort((a, b) => a.firstSequence - b.firstSequence);
}

export function actorInventory(events: TraceEvent[]): ActorInventory {
  const inventory: ActorInventory = { processes: 0, agents: 0, subagents: 0, humans: 0, systems: 0 };
  for (const actor of summarizeAgents(events)) {
    if (actor.type === 'process') inventory.processes += 1;
    else if (actor.type === 'agent') inventory.agents += 1;
    else if (actor.type === 'subagent') inventory.subagents += 1;
    else if (actor.type === 'human') inventory.humans += 1;
    else inventory.systems += 1;
  }
  return inventory;
}

/** How a trace that passed verification is protected. An unsigned trace is never presented as proof. */
export function integrityProtectionLabel(trace: TraceManifest): string {
  if (trace.integrity_protection === 'signed') return trace.integrity_signer ? `signed by ${trace.integrity_signer}` : 'signed';
  if (trace.integrity_protection === 'sealed') return 'unsigned, self-consistent only';
  if (trace.integrity_protection === 'digest_only') return 'unsigned, v1 digest only';
  return 'integrity verified';
}

export function runHealth(trace: TraceManifest, events: TraceEvent[]): RunHealth {
  const unreadable = unreadableHealth(trace);
  if (unreadable) return unreadable;
  return outcomeFrom(trace, {
    errors: events.filter(isIssue).length,
    refused: events.filter((event) => REFUSAL_STATUSES.has(event.status.trim().toLowerCase())).length,
    pending: awaitingApprovals(events).length
  });
}

/**
 * The outcome of a trace list row, from the manifest and the server's summary alone. It applies the
 * same rules in the same order as `runHealth`, so a row and the open run cannot disagree about how a
 * run ended. The summary counts issues but not which of them were refusals or pending approvals, so
 * those two states are only named once the run's events are loaded.
 */
export function listHealth(trace: TraceManifest): RunHealth {
  return unreadableHealth(trace) ?? outcomeFrom(trace, { errors: trace.summary?.issue_count ?? 0, refused: 0, pending: 0 });
}

/** States in which there is no outcome to report, because the trace cannot be trusted or read. */
function unreadableHealth(trace: TraceManifest): RunHealth | null {
  if (trace.integrity === 'invalid') {
    return {
      label: 'Unverified',
      tone: 'error',
      detail: trace.integrity_detail?.trim() || 'Journal failed integrity verification'
    };
  }
  if (trace.integrity === 'locked') {
    return {
      label: 'Locked',
      tone: 'warning',
      detail: trace.integrity_detail?.trim() || 'This trace is encrypted. Restart premier with --key-file to read it.'
    };
  }
  if (trace.integrity === 'unsupported') {
    return {
      label: 'Unsupported',
      tone: 'warning',
      detail: trace.integrity_detail?.trim() || 'This trace was written by a newer Premier. Upgrade premier to read it.'
    };
  }
  if (isAbandoned(trace)) {
    return {
      label: 'Abandoned',
      tone: 'warning',
      detail: trace.integrity_detail?.trim() || 'The recorder stopped before finalizing this trace. Run premier recover to finalize it.'
    };
  }
  return null;
}

function outcomeFrom(trace: TraceManifest, counts: { errors: number; refused: number; pending: number }): RunHealth {
  const { errors: errorCount, refused: deniedCount, pending: pendingCount } = counts;
  if (trace.termination?.kind === 'interrupted') {
    return { label: 'Interrupted', tone: 'warning', detail: 'Recovered after recorder interruption' };
  }
  if (trace.termination?.kind === 'signal') {
    const signal = trace.termination.signal_name?.trim() || (trace.termination.signal ? `signal ${trace.termination.signal}` : 'a signal');
    return { label: 'Failed', tone: 'error', detail: `Terminated by ${signal}` };
  }
  // Older manifests carry the exit status only in the termination block.
  const exitCode = trace.exit_code ?? trace.termination?.exit_code ?? null;
  if (exitCode !== null && exitCode !== 0) {
    return { label: 'Failed', tone: 'error', detail: `Exit ${exitCode}${errorCount ? ` · ${errorCount} error${errorCount === 1 ? '' : 's'}` : ''}` };
  }
  if (deniedCount) return { label: 'Blocked', tone: 'error', detail: `${deniedCount} denied, rejected or blocked operation${deniedCount === 1 ? '' : 's'}` };
  if (errorCount) return { label: 'Needs attention', tone: 'warning', detail: `${errorCount} recorded error${errorCount === 1 ? '' : 's'}${exitCode === 0 ? ' despite a clean exit' : ''}` };
  if (pendingCount) return { label: 'Awaiting approval', tone: 'warning', detail: `${pendingCount} pending decision${pendingCount === 1 ? '' : 's'}` };
  if (trace.ended_at === null || trace.integrity === 'live') return { label: 'Running', tone: 'running', detail: 'Trace is still receiving evidence' };
  // A run that ended without an exit status did not demonstrably succeed.
  if (exitCode === null) return { label: 'Unknown', tone: 'warning', detail: 'The run ended without a recorded exit status, so its outcome is not known' };
  const verified = trace.integrity === 'verified' ? ` · ${integrityProtectionLabel(trace)}` : '';
  return { label: 'Passed', tone: 'success', detail: `Clean exit with no recorded errors${verified}` };
}

/**
 * Terminal control sequences (colours, cursor movement, window titles) and the control characters
 * left around them. Recorded output keeps them; a one-line summary and the search box must not.
 */
const CONTROL_SEQUENCES = /\u001b\[[0-?]*[ -/]*[@-~]|\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\|$)|\u001b[PX^_][^\u001b]*(?:\u001b\\|$)|\u001b[@-Z\\-_]|\u001b|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

export function stripControlSequences(text: string): string {
  // A carriage return rewrites the line in a terminal; in flat text it only separates.
  return text.includes('\u001b') || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(text)
    ? text.replace(/\r/g, '\n').replace(CONTROL_SEQUENCES, '')
    : text;
}

function compact(value: unknown): string {
  let output: string;
  if (Array.isArray(value)) output = value.map(String).join(', ');
  else if (typeof value === 'object' && value !== null) output = JSON.stringify(value);
  else output = String(value);
  return stripControlSequences(output).replace(/\s+/g, ' ').trim();
}

function first(payload: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = payload[key];
    if (value !== undefined && value !== null && value !== '') return compact(value);
  }
  return null;
}

/** Provider text is unbounded; rows only need the opening of it. */
function excerpt(value: string | null, limit = 240): string | null {
  if (!value) return null;
  const flat = stripControlSequences(value).replace(/\s+/g, ' ').trim();
  if (!flat) return null;
  return flat.length > limit ? `${flat.slice(0, limit - 1)}…` : flat;
}

export function eventSummary(event: TraceEvent): string {
  let payload: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(event.payload_json);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      if (parsed === null) return 'null payload';
      if (Array.isArray(parsed)) return compact(parsed);
      return compact(parsed);
    }
    payload = parsed as Record<string, unknown>;
  } catch {
    return event.payload_json.trim() || event.source;
  }
  const kind = event.kind.toLowerCase();
  // Adapter events keep the provider object under payload.native; top-level fields win when present.
  const native = nativeOf(payload);
  const nativeError = native ? payloadError(payload) : null;
  /** What a provider event says for itself: its error, its text, or at least its native type. */
  const nativeFallback = (): string | null => native
    ? (nativeError ? `error: ${excerpt(nativeError)}` : null) ?? excerpt(nativeText(payload)) ?? nativeType(payload)
    : null;
  if (kind === 'session.start') {
    const goal = first(payload, ['goal']);
    const command = Array.isArray(payload.command) ? payload.command.map(String) : null;
    const executable = command?.[0] ?? first(payload, ['command']);
    const shellWrapper = command && ['sh', 'bash', 'zsh'].includes(command[0]) && command[1] === '-c';
    return goal ? `Goal: ${goal}` : shellWrapper ? 'Shell trace recording started' : executable ? `Started ${executable}` : 'Trace recording started';
  }
  if (kind.includes('stdout') || kind.includes('stderr') || kind === 'process.terminal') return first(payload, ['text'])?.replace(/\s+/g, ' ').trim() || 'Empty output';
  if (kind.startsWith('model.')) {
    const model = first(payload, ['model']) ?? payloadModel(payload);
    const content = first(payload, ['summary', 'text', 'content', 'response'])
      ?? (nativeError ? `error: ${excerpt(nativeError)}` : excerpt(nativeText(payload)));
    // Missing usage stays absent from the row; it is never rendered as "0 tokens".
    const tokens = first(payload, ['tokens', 'total_tokens']) ?? payloadTotalTokens(payload);
    return [model, content, tokens !== null ? `${tokens} tokens` : null].filter(Boolean).join(' · ') || 'Model response captured';
  }
  if (kind.startsWith('tool.')) {
    const namedTool = first(payload, ['tool', 'name', 'command']) || (native ? payloadTool(payload) : null);
    const tool = namedTool || (native ? (kind === 'tool.result' ? 'Tool result' : 'Tool call') : event.source);
    const exitCode = nativeExitCode(payload);
    const result = payload.failed !== undefined ? `failed: ${compact(payload.failed)}`
      : payload.error !== undefined ? `error: ${compact(payload.error)}`
      : payload.query !== undefined ? `query: ${compact(payload.query)}`
      : payload.checks !== undefined ? compact(payload.checks)
      : payload.missing !== undefined ? `${compact(payload.missing)} missing`
      : payload.matches !== undefined ? `${compact(payload.matches)} matches`
      : payload.files_changed !== undefined ? `${compact(payload.files_changed)} files changed`
      : first(payload, ['result', 'summary'])
        ?? (nativeError ? `error: ${excerpt(nativeError)}`
          : exitCode !== null ? `exit ${exitCode}`
          : native && !namedTool ? excerpt(nativeText(payload))
          : null);
    return result ? `${tool} · ${result}` : tool;
  }
  if (kind === 'approval.request') {
    const operation = first(payload, ['operation', 'action']) || (native ? payloadTool(payload) : null) || 'operation';
    const target = first(payload, ['files', 'resource', 'scope']);
    const reason = first(payload, ['reason']);
    return [`Request ${operation}`, target, reason].filter(Boolean).join(' · ');
  }
  if (kind === 'approval.decision') {
    const scope = first(payload, ['scope']);
    const receipt = first(payload, ['receipt', 'approval_receipt']);
    return [`${event.status || 'decision'}`, scope, receipt ? `receipt ${receipt}` : null].filter(Boolean).join(' · ');
  }
  if (kind.startsWith('agent.')) {
    const content = first(payload, ['task', 'finding', 'outcome', 'result', 'input', 'scope', 'action', 'message']);
    const delegates = first(payload, ['delegates', 'joined', 'to']);
    if (kind === 'agent.delegation' && delegates) return [`Delegated to ${delegates}`, content].filter(Boolean).join(' · ');
    if (kind === 'agent.join' && delegates) return [`Joined ${delegates}`, content].filter(Boolean).join(' · ');
    if (kind === 'agent.message' && delegates) return [`Sent to ${delegates}`, content].filter(Boolean).join(' · ');
    return content || nativeFallback() || event.source;
  }
  // The recorder could not start the command at all; the exit code alone would hide why.
  if (kind === 'process.spawn_failed') {
    const executable = first(payload, ['executable']);
    const reason = first(payload, ['error']);
    return [`Failed to start ${executable ?? 'the command'}`, reason].filter(Boolean).join(': ');
  }
  if (kind === 'process.exit' || typeof payload.exit_code === 'number') return `Exited with status ${payload.exit_code}`;
  return first(payload, ['summary', 'text', 'message', 'operation', 'command']) || nativeFallback() || event.source;
}

/**
 * Rows for `events` (what is shown), measured against `journal` (the whole run): elapsed time is
 * counted from the run's first event and causal depth follows parents wherever they are, so neither
 * changes with the active filter or time crop.
 */
export function timelineLayout(events: TraceEvent[], journal: TraceEvent[] = events): { lanes: string[]; events: TimelineEvent[] } {
  const lanes = [...new Set(events.map(actorId))];
  const startedAt = traceTimeBounds(journal)?.start ?? Number.NaN;
  const resolveParent = parentResolver(journal);
  const depthMemo = new Map<string, number>();
  const depthOf = (event: TraceEvent): number => {
    // Walk up iteratively: a deep chain must not overflow the stack, and a cycle must end.
    const chain: TraceEvent[] = [];
    const seen = new Set<string>();
    let current: TraceEvent | null = event;
    let base = 0;
    while (current) {
      const known = depthMemo.get(current.event_id);
      if (known !== undefined) { base = known + 1; break; }
      if (seen.has(current.event_id)) break;
      seen.add(current.event_id);
      chain.push(current);
      current = resolveParent(current).found;
    }
    for (let index = chain.length - 1; index >= 0; index -= 1) {
      depthMemo.set(chain[index].event_id, Math.min(base, 8));
      base += 1;
    }
    return depthMemo.get(event.event_id) ?? 0;
  };
  return {
    lanes,
    events: events.map((event) => {
      const parent = resolveParent(event).found;
      const timestamp = Date.parse(event.timestamp);
      const parentLane = parent ? lanes.indexOf(actorId(parent)) : -1;
      return {
        ...event,
        lane: lanes.indexOf(actorId(event)),
        parentLane: parentLane >= 0 ? parentLane : null,
        depth: depthOf(event),
        elapsedMs: Number.isFinite(timestamp) && Number.isFinite(startedAt) ? Math.max(0, timestamp - startedAt) : 0
      };
    })
  };
}

export function filterEvents(events: TraceEvent[], filters: EventFilters): TraceEvent[] {
  const query = filters.search.trim().toLowerCase();
  return events.filter((event) => {
    if (filters.actorId && actorId(event) !== filters.actorId) return false;
    if (filters.correlationId && event.correlation_id !== filters.correlationId) return false;
    if (filters.errorsOnly && !isIssue(event)) return false;
    if (filters.category === 'error' && !isIssue(event)) return false;
    if (filters.category !== 'all' && filters.category !== 'error' && familyOf(event) !== filters.category) return false;
    if (!query) return true;
    return searchText(event).includes(query);
  });
}

/** Every string in a decoded payload, one per line. */
function collectStrings(value: unknown, output: string[]): void {
  if (typeof value === 'string') output.push(value);
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, output);
  else if (value !== null && typeof value === 'object') for (const item of Object.values(value)) collectStrings(item, output);
}

/**
 * What the search box looks in, the same as `premier query --search`: the event's fields and ids,
 * its payload as JSON text (so key names match), and every payload string as it was recorded, with
 * and without terminal control sequences, so text with quotes, line breaks or colour codes matches
 * as it is displayed.
 */
function searchText(event: TraceEvent): string {
  const parts = [
    event.kind, event.source, actorId(event), event.actor_type, event.status,
    event.event_id, event.span_id, event.parent_span_id, event.parent_event_id, event.correlation_id,
    event.timestamp, event.payload_json, ...event.links
  ];
  // Only an escaped character makes the decoded text differ from the JSON.
  if (event.payload_json.includes('\\')) {
    try {
      const decoded: string[] = [];
      collectStrings(JSON.parse(event.payload_json), decoded);
      const text = decoded.join('\n');
      parts.push(text);
      const plain = stripControlSequences(text);
      if (plain !== text) parts.push(plain);
    } catch {
      // A payload that is not JSON is searched as the text it is.
    }
  }
  return parts.join(' ').toLowerCase();
}

export function countByCategory(events: TraceEvent[], category: EventCategory): number {
  if (category === 'all') return events.length;
  if (category === 'error') return events.filter(isIssue).length;
  return events.filter((event) => familyOf(event) === category).length;
}

/**
 * First timestamp and overall span of a journal, from the first to the last time an event was
 * received. A reported duration is elapsed time that ended at the event, so it never extends the
 * run past its last event, and an event whose timestamp cannot be parsed has no place on the clock.
 * Written as a loop on purpose: spreading a large journal into Math.min/Math.max overflows the call
 * stack above roughly 125k events.
 */
export function traceTimeBounds(input: TraceEvent[]): { start: number; span: number } | null {
  let start = Number.POSITIVE_INFINITY;
  let end = Number.NEGATIVE_INFINITY;
  for (const event of input) {
    const timestamp = Date.parse(event.timestamp);
    if (!Number.isFinite(timestamp)) continue;
    if (timestamp < start) start = timestamp;
    if (timestamp > end) end = timestamp;
  }
  if (!Number.isFinite(start)) return null;
  return { start, span: Math.max(1, end - start) };
}

/** Kinds the recorder writes for raw output: pipes, and one PTY stream under `record --pty`. */
export const PROCESS_OUTPUT_KINDS = ['process.stdout', 'process.stderr', 'process.terminal'];

export function isProcessNoise(event: TraceEvent): boolean {
  return PROCESS_OUTPUT_KINDS.includes(event.kind) && !isIssue(event);
}

export function materialEvent(events: TraceEvent[]): TraceEvent | null {
  return events.find(isIssue)
    ?? events.find((event) => event.kind.startsWith('approval.'))
    ?? events.find((event) => event.kind.startsWith('tool.') || event.kind.startsWith('model.'))
    ?? events.find((event) => event.kind === 'agent.join' || event.kind === 'agent.delegation')
    ?? events.find((event) => !isProcessNoise(event))
    ?? events[0]
    ?? null;
}
