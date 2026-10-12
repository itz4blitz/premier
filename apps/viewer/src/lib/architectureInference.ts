import { actorId, actorRole, filterEvents, isIssue, type ActorRole } from './analysis';
import { parentResolver } from './causal';
import type { EventFilters, TraceEvent } from './types';

export type EvidenceConfidence = 'recorded' | 'high' | 'observation-only';
export type RelationshipSource = 'parent-event' | 'parent-span' | 'link' | 'correlation';

export interface ArchitectureWindow {
  startMs: number;
  endMs: number;
  durationMs: number;
}

export interface ArchitectureActor {
  id: string;
  role: ActorRole;
  eventCount: number;
  issueCount: number;
  eventKinds: Record<string, number>;
  firstSequence: number;
  /** Overall first-to-last envelope of observed activity. */
  window: ArchitectureWindow | null;
  /**
   * Contiguous activity segments after idle gaps are split.
   * Prefer rendering these over the full envelope so late-starting or intermittent
   * agents do not look continuously active from the run origin.
   */
  segments: ArchitectureWindow[];
  /** `recorded` only when every event of this actor carried its actor_id. */
  confidence: EvidenceConfidence;
  source: 'actor-id' | 'fallback-root';
  /** Whether a producer stated this role (`actor_type`) or the viewer worked it out. */
  roleSource: 'recorded' | 'inferred';
  /** The distinct `actor_type` values recorded for this actor, as written. */
  recordedTypes: string[];
  /** Events with no actor_id that were grouped under this actor. */
  unattributedEventCount: number;
}

export interface ArchitectureConnection {
  id: string;
  sourceActorId: string;
  targetActorId: string;
  eventCount: number;
  issueCount: number;
  eventKinds: Record<string, number>;
  eventIds: string[];
  sources: RelationshipSource[];
  confidence: 'recorded' | 'high';
  parentEvidenceInScope: boolean;
  /** Issues recorded in the events caused, directly or indirectly, by this connection's events. */
  downstreamIssueCount: number;
  /** A causal connection in either direction joins the same two actors. */
  causallyConnected: boolean;
}

export interface ArchitectureConcurrencySample {
  timestampMs: number;
  activeActorIds: string[];
  activeActorCount: number;
  activeEventCount: number;
}

export interface ArchitectureCoPresence {
  actorIds: [string, string];
  overlap: ArchitectureWindow;
  explicitlyConnected: boolean;
  confidence: 'observation-only';
  source: 'temporal-overlap';
  isRelationship: false;
}

export interface UnresolvedParent {
  eventId: string;
  actorId: string;
  reference: string;
  referenceType: 'parent-event' | 'parent-span';
  reason: 'missing' | 'ambiguous-span' | 'source-outside-scope';
}

export interface ArchitectureInference {
  actors: ArchitectureActor[];
  /** Parent-to-child connections: a recorded parent event, or an unambiguous parent span. */
  connections: ArchitectureConnection[];
  /**
   * Actors that refer to each other without a parent/child meaning: an event's `links`, or a shared
   * correlation id. They have no direction; `sourceActorId` is the one seen first.
   */
  references: ArchitectureConnection[];
  concurrency: ArchitectureConcurrencySample[];
  coPresence: ArchitectureCoPresence[];
  unlinkedActorIds: string[];
  unresolvedParents: UnresolvedParent[];
  scope: {
    inputEventCount: number;
    eventCount: number;
    filtered: boolean;
    temporalEventCount: number;
    startMs: number | null;
    endMs: number | null;
  };
}

export interface ArchitectureInferenceOptions {
  filters?: EventFilters;
  predicate?: (event: TraceEvent) => boolean;
}

interface ActorAccumulator {
  actor: ArchitectureActor;
  starts: number[];
  ends: number[];
}

function timestampOf(event: TraceEvent): number | null {
  const timestamp = Date.parse(event.timestamp);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function intervalOf(event: TraceEvent): ArchitectureWindow | null {
  const startMs = timestampOf(event);
  if (startMs === null) return null;
  const durationMs = Number.isFinite(event.duration_ms) ? Math.max(0, event.duration_ms) : 0;
  return { startMs, endMs: startMs + durationMs, durationMs };
}

function increment(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}

function mergeIntervals(intervals: ArchitectureWindow[]): ArchitectureWindow[] {
  if (!intervals.length) return [];
  const sorted = [...intervals].sort((a, b) => a.startMs - b.startMs || a.endMs - b.endMs);
  const merged: ArchitectureWindow[] = [{ ...sorted[0] }];
  for (let index = 1; index < sorted.length; index += 1) {
    const current = sorted[index];
    const last = merged[merged.length - 1];
    if (current.startMs <= last.endMs) {
      last.endMs = Math.max(last.endMs, current.endMs);
      last.durationMs = Math.max(0, last.endMs - last.startMs);
    } else {
      merged.push({ ...current });
    }
  }
  return merged;
}

/** Split idle gaps so intermittent agents are not painted as continuous from first to last. */
export function activitySegments(
  intervals: ArchitectureWindow[],
  gapMs: number
): ArchitectureWindow[] {
  const merged = mergeIntervals(intervals);
  if (merged.length <= 1) return merged;
  const segments: ArchitectureWindow[] = [];
  let current = { ...merged[0] };
  for (let index = 1; index < merged.length; index += 1) {
    const next = merged[index];
    if (next.startMs <= current.endMs + gapMs) {
      current.endMs = Math.max(current.endMs, next.endMs);
      current.durationMs = Math.max(0, current.endMs - current.startMs);
    } else {
      segments.push(current);
      current = { ...next };
    }
  }
  segments.push(current);
  return segments;
}

/** Prefer orchestrator / main agent as the starting plane of the actor list. */
export function orchestratorRank(actor: Pick<ArchitectureActor, 'id' | 'role'>): number {
  const id = actor.id.trim().toLowerCase();
  const orchestratorNames = [
    'coordinator',
    'orchestrator',
    'supervisor',
    'conductor',
    'manager',
    'main',
    'primary',
    'root',
    'planner'
  ];
  if (orchestratorNames.some((name) => id === name || id.startsWith(`${name}-`) || id.endsWith(`-${name}`))) {
    return 0;
  }
  if (actor.role === 'agent') return 1;
  if (actor.role === 'process' && id === 'root') return 2;
  if (actor.role === 'human') return 3;
  if (actor.role === 'system') return 4;
  if (actor.role === 'subagent') return 5;
  if (actor.role === 'process') return 6;
  return 7;
}

function compareActors(a: ArchitectureActor, b: ArchitectureActor): number {
  const rank = orchestratorRank(a) - orchestratorRank(b);
  if (rank !== 0) return rank;
  const aStart = a.window?.startMs ?? Number.POSITIVE_INFINITY;
  const bStart = b.window?.startMs ?? Number.POSITIVE_INFINITY;
  if (aStart !== bStart) return aStart - bStart;
  return a.firstSequence - b.firstSequence;
}

function scopedEvents(events: TraceEvent[], options: ArchitectureInferenceOptions): TraceEvent[] {
  let scoped = options.filters ? filterEvents(events, options.filters) : [...events];
  if (options.predicate) scoped = scoped.filter(options.predicate);
  return scoped;
}

const KNOWN_ROLES = ['process', 'agent', 'subagent', 'human', 'system'];

/**
 * Builds an evidence-backed architecture model from recorded trace events.
 * Only parent_event_id and unambiguous parent_span_id references become connections; `links` and
 * shared correlation ids are returned as undirected references. Temporal overlap is returned
 * separately and is never promoted to a relationship. Parents are resolved against all of
 * `events`, so pass the whole journal and narrow with `options`.
 */
export function inferArchitecture(
  events: TraceEvent[],
  options: ArchitectureInferenceOptions = {}
): ArchitectureInference {
  const scoped = scopedEvents(events, options).sort((a, b) => a.sequence - b.sequence);
  const scopedIds = new Set(scoped.map((event) => event.event_id));
  const actors = new Map<string, ActorAccumulator>();

  for (const event of scoped) {
    const id = actorId(event);
    const accumulator = actors.get(id) ?? {
      actor: {
        id,
        role: actorRole(event),
        eventCount: 0,
        issueCount: 0,
        eventKinds: {},
        firstSequence: event.sequence,
        window: null,
        segments: [],
        confidence: 'recorded',
        source: 'actor-id',
        roleSource: 'inferred',
        recordedTypes: [],
        unattributedEventCount: 0
      },
      starts: [],
      ends: []
    };
    if (!event.actor_id) {
      // An event that names no actor is only grouped here; it says nothing about who this is.
      accumulator.actor.unattributedEventCount += 1;
      accumulator.actor.confidence = 'high';
      accumulator.actor.source = 'fallback-root';
    } else if (accumulator.actor.role === 'process' && actorRole(event) !== 'process') {
      // Prefer the more specific role an attributed event states over a generic process label.
      accumulator.actor.role = actorRole(event);
    }
    const recordedType = event.actor_type?.trim();
    if (recordedType && !accumulator.actor.recordedTypes.includes(recordedType)) accumulator.actor.recordedTypes.push(recordedType);
    accumulator.actor.eventCount += 1;
    accumulator.actor.issueCount += isIssue(event) ? 1 : 0;
    increment(accumulator.actor.eventKinds, event.kind);
    accumulator.actor.firstSequence = Math.min(accumulator.actor.firstSequence, event.sequence);
    const interval = intervalOf(event);
    if (interval) {
      accumulator.starts.push(interval.startMs);
      accumulator.ends.push(interval.endMs);
    }
    actors.set(id, accumulator);
  }
  for (const { actor } of actors.values()) {
    actor.roleSource = actor.recordedTypes.some((type) => type.toLowerCase() === actor.role) ? 'recorded' : 'inferred';
    if (actor.recordedTypes.some((type) => !KNOWN_ROLES.includes(type.toLowerCase()))) actor.roleSource = 'inferred';
  }

  // Loops, not Math.min(...values): spreading a large journal overflows the call stack.
  let earliest = Number.POSITIVE_INFINITY;
  let latest = Number.NEGATIVE_INFINITY;
  for (const entry of actors.values()) {
    for (const startMs of entry.starts) if (startMs < earliest) earliest = startMs;
    for (const endMs of entry.ends) if (endMs > latest) latest = endMs;
  }
  const runStart = Number.isFinite(earliest) ? earliest : 0;
  const runEnd = Number.isFinite(latest) ? latest : runStart;
  const runSpan = Math.max(0, runEnd - runStart);
  // Gap threshold: idle stretches beyond 8% of the run (min 400ms, max 30s) break activity segments.
  const gapMs = Math.min(30_000, Math.max(400, runSpan * 0.08));

  for (const accumulator of actors.values()) {
    if (!accumulator.starts.length) continue;
    const intervals = accumulator.starts.map((startMs, index) => {
      const endMs = accumulator.ends[index] ?? startMs;
      return { startMs, endMs, durationMs: Math.max(0, endMs - startMs) };
    });
    const segments = activitySegments(intervals, gapMs);
    accumulator.actor.segments = segments;
    // activitySegments always yields at least one segment for a non-empty interval list.
    const startMs = segments[0].startMs;
    const endMs = segments[segments.length - 1].endMs;
    accumulator.actor.window = { startMs, endMs, durationMs: Math.max(0, endMs - startMs) };
  }

  // One parent rule for the inspector, the timeline and this map; see causal.parentResolver.
  const resolveParent = parentResolver(events);
  const byEvent = new Map<string, TraceEvent>();
  const spanOpeners = new Map<string, TraceEvent>();
  const spanActors = new Map<string, Set<string>>();
  for (const event of events) {
    if (!byEvent.has(event.event_id)) byEvent.set(event.event_id, event);
    if (!event.span_id) continue;
    const opener = spanOpeners.get(event.span_id);
    if (!opener || event.sequence < opener.sequence) spanOpeners.set(event.span_id, event);
    const owners = spanActors.get(event.span_id) ?? new Set<string>();
    owners.add(actorId(event));
    spanActors.set(event.span_id, owners);
  }

  const connections = new Map<string, ArchitectureConnection>();
  const unresolvedParents: UnresolvedParent[] = [];
  const connect = (
    target: Map<string, ArchitectureConnection>,
    sourceActorId: string,
    targetActorId: string,
    event: TraceEvent,
    source: RelationshipSource,
    evidenceInScope: boolean
  ) => {
    const id = `${sourceActorId}\u0000${targetActorId}`;
    const recorded = source !== 'parent-span';
    const connection = target.get(id) ?? {
      id,
      sourceActorId,
      targetActorId,
      eventCount: 0,
      issueCount: 0,
      eventKinds: {},
      eventIds: [],
      sources: [],
      confidence: recorded ? 'recorded' : 'high',
      parentEvidenceInScope: true,
      downstreamIssueCount: 0,
      causallyConnected: false
    };
    if (!connection.eventIds.includes(event.event_id)) {
      connection.eventCount += 1;
      connection.issueCount += isIssue(event) ? 1 : 0;
      increment(connection.eventKinds, event.kind);
      connection.eventIds.push(event.event_id);
    }
    if (!connection.sources.includes(source)) connection.sources.push(source);
    if (recorded) connection.confidence = 'recorded';
    connection.parentEvidenceInScope &&= evidenceInScope;
    target.set(id, connection);
  };

  /** Scoped events by the scoped event that caused them, for rolling issues up to a handoff. */
  const parentOfScoped = new Map<string, string>();
  for (const event of scoped) {
    const resolution = resolveParent(event);
    const ambiguousSpan = Boolean(event.parent_span_id) && (spanActors.get(event.parent_span_id)?.size ?? 0) > 1;
    let parent: TraceEvent | null = null;
    let source: RelationshipSource | null = null;

    if (resolution.found && resolution.via === 'event') {
      parent = resolution.found;
      source = 'parent-event';
    } else if (event.parent_span_id && ambiguousSpan) {
      unresolvedParents.push({ eventId: event.event_id, actorId: actorId(event), reference: event.parent_span_id, referenceType: 'parent-span', reason: 'ambiguous-span' });
      continue;
    } else if (resolution.found) {
      parent = resolution.found;
      source = 'parent-span';
    } else if (resolution.missing) {
      unresolvedParents.push({
        eventId: event.event_id,
        actorId: actorId(event),
        reference: resolution.reference,
        referenceType: resolution.via === 'span' ? 'parent-span' : 'parent-event',
        reason: 'missing'
      });
      continue;
    }
    if (!parent || !source) continue;
    if (scopedIds.has(parent.event_id) && parent.sequence < event.sequence) parentOfScoped.set(event.event_id, parent.event_id);

    const sourceActorId = actorId(parent);
    const targetActorId = actorId(event);
    if (sourceActorId !== targetActorId) {
      if (!actors.has(sourceActorId)) {
        unresolvedParents.push({
          eventId: event.event_id,
          actorId: targetActorId,
          reference: resolution.reference,
          referenceType: source === 'parent-span' ? 'parent-span' : 'parent-event',
          reason: 'source-outside-scope'
        });
      } else {
        connect(connections, sourceActorId, targetActorId, event, source, scopedIds.has(parent.event_id));
      }
    }
    // A parent span that belongs to a third actor is evidence too; the event parent does not erase it.
    if (source === 'parent-event' && event.parent_span_id && !ambiguousSpan) {
      const opener = spanOpeners.get(event.parent_span_id);
      const spanActorId = opener && opener.event_id !== event.event_id ? actorId(opener) : null;
      if (opener && spanActorId && spanActorId !== sourceActorId && spanActorId !== targetActorId && actors.has(spanActorId)) {
        connect(connections, spanActorId, targetActorId, event, 'parent-span', scopedIds.has(opener.event_id));
      }
    }
  }

  // Issues among the events a handoff led to. Children follow their parents in the journal, so one
  // pass from the last event to the first sums each subtree without recursion.
  const subtreeIssues = new Map<string, number>();
  for (let index = scoped.length - 1; index >= 0; index -= 1) {
    const event = scoped[index];
    const total = (subtreeIssues.get(event.event_id) ?? 0) + (isIssue(event) ? 1 : 0);
    subtreeIssues.set(event.event_id, total);
    const parentId = parentOfScoped.get(event.event_id);
    if (parentId) subtreeIssues.set(parentId, (subtreeIssues.get(parentId) ?? 0) + total);
  }
  for (const connection of connections.values()) {
    const boundary = new Set(connection.eventIds);
    let downstream = 0;
    for (const eventId of connection.eventIds) {
      // A boundary event under another boundary event of this connection is already in its sum.
      let ancestor = parentOfScoped.get(eventId);
      let nested = false;
      while (ancestor) {
        if (boundary.has(ancestor)) { nested = true; break; }
        ancestor = parentOfScoped.get(ancestor);
      }
      if (!nested) downstream += subtreeIssues.get(eventId) ?? 0;
    }
    connection.downstreamIssueCount = Math.max(0, downstream - connection.issueCount);
    connection.causallyConnected = true;
  }

  // References: `links` and shared correlation ids. They say two actors touched the same work, not
  // that one caused the other, so they are kept apart from connections and have no direction.
  const references = new Map<string, ArchitectureConnection>();
  const firstSeen = (actor: string) => actors.get(actor)?.actor.firstSequence ?? Number.POSITIVE_INFINITY;
  const refer = (left: string, right: string, event: TraceEvent, source: RelationshipSource, inScope: boolean) => {
    if (left === right || !actors.has(left) || !actors.has(right)) return;
    const [first, second] = firstSeen(left) <= firstSeen(right) ? [left, right] : [right, left];
    connect(references, first, second, event, source, inScope);
  };
  const correlated = new Map<string, TraceEvent[]>();
  for (const event of scoped) {
    for (const link of event.links) {
      const target = byEvent.get(link) ?? spanOpeners.get(link);
      if (target && target.event_id !== event.event_id) refer(actorId(event), actorId(target), event, 'link', scopedIds.has(target.event_id));
    }
    if (event.correlation_id) {
      const group = correlated.get(event.correlation_id) ?? [];
      group.push(event);
      correlated.set(event.correlation_id, group);
    }
  }
  for (const group of correlated.values()) {
    const origin = group[0];
    for (const event of group) refer(actorId(origin), actorId(event), event, 'correlation', true);
  }
  for (const reference of references.values()) {
    reference.causallyConnected = connections.has(`${reference.sourceActorId}\u0000${reference.targetActorId}`)
      || connections.has(`${reference.targetActorId}\u0000${reference.sourceActorId}`);
  }

  const temporalEvents = scoped
    .map((event) => ({ event, interval: intervalOf(event) }))
    .filter((entry): entry is { event: TraceEvent; interval: ArchitectureWindow } => entry.interval !== null);
  const boundaryMap = new Map<number, { starts: typeof temporalEvents; ends: typeof temporalEvents }>();
  for (const entry of temporalEvents) {
    const startBoundary = boundaryMap.get(entry.interval.startMs) ?? { starts: [], ends: [] };
    startBoundary.starts.push(entry);
    boundaryMap.set(entry.interval.startMs, startBoundary);
    const endBoundary = boundaryMap.get(entry.interval.endMs) ?? { starts: [], ends: [] };
    endBoundary.ends.push(entry);
    boundaryMap.set(entry.interval.endMs, endBoundary);
  }
  const boundaries = [...boundaryMap.keys()].sort((a, b) => a - b);
  const active = new Map<string, TraceEvent>();
  const concurrency = boundaries.map((timestampMs) => {
    const boundary = boundaryMap.get(timestampMs)!;
    for (const { event } of boundary.starts) active.set(event.event_id, event);
    const activeActorIds = [...new Set([...active.values()].map(actorId))];
    const sample = { timestampMs, activeActorIds, activeActorCount: activeActorIds.length, activeEventCount: active.size };
    for (const { event } of boundary.ends) active.delete(event.event_id);
    return sample;
  });

  const actorList = [...actors.values()].map(({ actor }) => actor).sort(compareActors);
  const connectedActors = new Set([...connections.values()].flatMap((edge) => [edge.sourceActorId, edge.targetActorId]));
  const coPresence: ArchitectureCoPresence[] = [];
  for (let index = 0; index < actorList.length; index += 1) {
    const left = actorList[index];
    if (!left.window) continue;
    for (let peerIndex = index + 1; peerIndex < actorList.length; peerIndex += 1) {
      const right = actorList[peerIndex];
      if (!right.window) continue;
      const startMs = Math.max(left.window.startMs, right.window.startMs);
      const endMs = Math.min(left.window.endMs, right.window.endMs);
      if (startMs > endMs) continue;
      const explicitlyConnected = connections.has(`${left.id}\u0000${right.id}`) || connections.has(`${right.id}\u0000${left.id}`);
      coPresence.push({
        actorIds: [left.id, right.id],
        overlap: { startMs, endMs, durationMs: Math.max(0, endMs - startMs) },
        explicitlyConnected,
        confidence: 'observation-only',
        source: 'temporal-overlap',
        isRelationship: false
      });
    }
  }

  return {
    actors: actorList,
    connections: [...connections.values()],
    references: [...references.values()],
    concurrency,
    coPresence,
    unlinkedActorIds: actorList.filter((actor) => !connectedActors.has(actor.id)).map((actor) => actor.id),
    unresolvedParents,
    scope: {
      inputEventCount: events.length,
      eventCount: scoped.length,
      filtered: scoped.length !== events.length,
      temporalEventCount: temporalEvents.length,
      startMs: boundaries[0] ?? null,
      endMs: boundaries.at(-1) ?? null
    }
  };
}
