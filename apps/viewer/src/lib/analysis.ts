import { nativeExitCode, nativeFailure, nativeOf, nativeText, nativeType, payloadError, payloadModel, payloadTool, payloadTotalTokens, record } from './nativePayload';
import { isAbandoned, type EventCategory, type EventFilters, type TraceEvent, type TraceManifest } from './types';

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
  label: 'Running' | 'Abandoned' | 'Awaiting approval' | 'Blocked' | 'Needs attention' | 'Interrupted' | 'Failed' | 'Passed' | 'Unverified';
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

/**
 * The one authoritative issue predicate for the viewer.
 * Keep this aligned with the recorder summary contract in premier-cli.
 */
export function isIssue(event: TraceEvent): boolean {
  const status = event.status.trim().toLowerCase();
  const kind = event.kind.trim().toLowerCase();
  return ['error', 'failed', 'denied', 'blocked'].includes(status)
    || kind.includes('error')
    || kind.includes('fail')
    || statesNativeFailure(event);
}

const nativeFailures = new WeakMap<TraceEvent, boolean>();

/**
 * Older adapter traces record a provider's explicit failure only under payload.native.
 * The predicate runs for every row and count, so the decoded answer is kept per event.
 */
function statesNativeFailure(event: TraceEvent): boolean {
  // Most events are not adapter envelopes; skip decoding their payload.
  if (!event.payload_json.includes('"native"')) return false;
  const known = nativeFailures.get(event);
  if (known !== undefined) return known;
  let failed = false;
  try {
    const payload = record(JSON.parse(event.payload_json));
    failed = payload !== null && nativeFailure(payload, event.correlation_id);
  } catch {
    failed = false;
  }
  nativeFailures.set(event, failed);
  return failed;
}

/**
 * Pending events nobody has answered yet. A request is settled by a later `approval.decision`, or by
 * any later approved/denied event, that shares its correlation id or span.
 */
export function awaitingApprovals(events: TraceEvent[]): TraceEvent[] {
  const decidedCorrelations = new Set<string>();
  const decidedSpans = new Set<string>();
  const awaiting: TraceEvent[] = [];
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    const status = event.status.trim().toLowerCase();
    if (status === 'pending') {
      const settled = (event.correlation_id !== '' && decidedCorrelations.has(event.correlation_id))
        || (event.span_id !== '' && decidedSpans.has(event.span_id));
      if (!settled) awaiting.push(event);
      continue;
    }
    if (['approved', 'denied'].includes(status) || event.kind.trim().toLowerCase() === 'approval.decision') {
      if (event.correlation_id) decidedCorrelations.add(event.correlation_id);
      if (event.span_id) decidedSpans.add(event.span_id);
    }
  }
  return awaiting.reverse();
}

export function categoryOf(event: TraceEvent): EventCategory {
  if (isIssue(event)) return 'error';
  const prefix = event.kind.split('.')[0] as EventCategory;
  return ['agent', 'model', 'tool', 'approval', 'process'].includes(prefix) ? prefix : 'agent';
}

/** The recorded family stays stable even when an event is also an issue. */
export function familyOf(event: TraceEvent): Exclude<EventCategory, 'all' | 'error'> | 'agent' {
  const prefix = event.kind.split('.')[0] as Exclude<EventCategory, 'all' | 'error'>;
  return ['agent', 'model', 'tool', 'approval', 'process'].includes(prefix) ? prefix : 'agent';
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
    if (categoryOf(event) === 'error' || ['failed', 'denied', 'blocked'].includes(event.status)) {
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
  if (trace.integrity === 'invalid') {
    return {
      label: 'Unverified',
      tone: 'error',
      detail: trace.integrity_detail?.trim() || 'Journal failed integrity verification'
    };
  }
  if (isAbandoned(trace)) {
    return {
      label: 'Abandoned',
      tone: 'warning',
      detail: trace.integrity_detail?.trim() || 'The recorder stopped before finalizing this trace. Run premier recover to finalize it.'
    };
  }
  const errorCount = events.filter((event) => categoryOf(event) === 'error').length;
  const deniedCount = events.filter((event) => ['denied', 'blocked'].includes(event.status)).length;
  const pendingCount = awaitingApprovals(events).length;
  if (trace.termination?.kind === 'interrupted') {
    return { label: 'Interrupted', tone: 'warning', detail: 'Recovered after recorder interruption' };
  }
  if (trace.termination?.kind === 'signal') {
    const signal = trace.termination.signal_name?.trim() || (trace.termination.signal ? `signal ${trace.termination.signal}` : 'a signal');
    return { label: 'Failed', tone: 'error', detail: `Terminated by ${signal}` };
  }
  if (trace.exit_code !== null && trace.exit_code !== 0) {
    return { label: 'Failed', tone: 'error', detail: `Exit ${trace.exit_code}${errorCount ? ` · ${errorCount} error${errorCount === 1 ? '' : 's'}` : ''}` };
  }
  if (deniedCount) return { label: 'Blocked', tone: 'error', detail: `${deniedCount} denied or blocked operation${deniedCount === 1 ? '' : 's'}` };
  if (errorCount) return { label: 'Needs attention', tone: 'warning', detail: `${errorCount} recorded error${errorCount === 1 ? '' : 's'} despite a clean exit` };
  if (pendingCount) return { label: 'Awaiting approval', tone: 'warning', detail: `${pendingCount} pending decision${pendingCount === 1 ? '' : 's'}` };
  if (trace.ended_at === null || trace.integrity === 'live') return { label: 'Running', tone: 'running', detail: 'Trace is still receiving evidence' };
  const verified = trace.integrity === 'verified' ? ` · ${integrityProtectionLabel(trace)}` : '';
  return { label: 'Passed', tone: 'success', detail: `Clean exit with no recorded errors${verified}` };
}

function compact(value: unknown): string {
  let output: string;
  if (Array.isArray(value)) output = value.map(String).join(', ');
  else if (typeof value === 'object' && value !== null) output = JSON.stringify(value);
  else output = String(value);
  return output.replace(/\s+/g, ' ').trim();
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
  const flat = value.replace(/\s+/g, ' ').trim();
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
  if (kind.includes('stdout') || kind.includes('stderr')) return first(payload, ['text'])?.replace(/\s+/g, ' ').trim() || 'Empty output';
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

export function timelineLayout(events: TraceEvent[]): { lanes: string[]; events: TimelineEvent[] } {
  const lanes = [...new Set(events.map(actorId))];
  const startedAt = events.length ? Date.parse(events[0].timestamp) : 0;
  const byEvent = new Map(events.map((event) => [event.event_id, event]));
  const firstBySpan = new Map<string, TraceEvent>();
  for (const event of events) if (event.span_id && !firstBySpan.has(event.span_id)) firstBySpan.set(event.span_id, event);
  const depthMemo = new Map<string, number>();
  const depthOf = (event: TraceEvent, seen = new Set<string>()): number => {
    if (depthMemo.has(event.event_id)) return depthMemo.get(event.event_id)!;
    if (seen.has(event.event_id)) return 0;
    seen.add(event.event_id);
    const parent = byEvent.get(event.parent_event_id) ?? firstBySpan.get(event.parent_span_id);
    const depth = parent && parent.event_id !== event.event_id ? Math.min(depthOf(parent, seen) + 1, 8) : 0;
    depthMemo.set(event.event_id, depth);
    return depth;
  };
  return {
    lanes,
    events: events.map((event) => {
      const parent = byEvent.get(event.parent_event_id) ?? firstBySpan.get(event.parent_span_id);
      return {
        ...event,
        lane: lanes.indexOf(actorId(event)),
        parentLane: parent ? lanes.indexOf(actorId(parent)) : null,
        depth: depthOf(event),
        elapsedMs: Math.max(0, Date.parse(event.timestamp) - startedAt)
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
    return [
      event.kind, event.source, actorId(event), event.status,
      event.event_id, event.span_id, event.parent_span_id, event.correlation_id, event.payload_json
    ]
      .join(' ')
      .toLowerCase()
      .includes(query);
  });
}

export function countByCategory(events: TraceEvent[], category: EventCategory): number {
  if (category === 'all') return events.length;
  if (category === 'error') return events.filter(isIssue).length;
  return events.filter((event) => familyOf(event) === category).length;
}

/**
 * First timestamp and overall span of a journal. Written as a loop on purpose: spreading a large
 * journal into Math.min/Math.max overflows the call stack above roughly 125k events.
 */
export function traceTimeBounds(input: TraceEvent[]): { start: number; span: number } | null {
  let start = Number.POSITIVE_INFINITY;
  let end = Number.NEGATIVE_INFINITY;
  for (const event of input) {
    const timestamp = Date.parse(event.timestamp);
    if (!Number.isFinite(timestamp)) continue;
    if (timestamp < start) start = timestamp;
    const finished = timestamp + Math.max(0, event.duration_ms || 0);
    if (finished > end) end = finished;
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
