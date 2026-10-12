import type { TraceEvent } from './types';

export interface RelatedEventTarget {
  id: string;
  kind: 'parent' | 'child' | 'link' | 'correlation';
  present: boolean;
  event?: TraceEvent;
}

/** How a parent was (or would have been) resolved, and the identifier that names it. */
export interface ParentResolution {
  found: TraceEvent | null;
  /** A parent was referenced but no recorded event matches it. */
  missing: boolean;
  via: 'event' | 'span' | null;
  reference: string;
}

export interface LinkResolution {
  id: string;
  found: TraceEvent | null;
  missing: boolean;
}

const noParent: ParentResolution = { found: null, missing: false, via: null, reference: '' };

export function findEventById(events: TraceEvent[], id: string): TraceEvent | undefined {
  return events.find((event) => event.event_id === id || event.span_id === id);
}

/**
 * One parent resolver for the inspector, the timeline's nesting depth, and the topology, so the
 * three never disagree. A recorded parent_event_id wins; otherwise (or when that id is not in the
 * journal) the parent is the event that opened parent_span_id: the lowest-sequence event carrying
 * that span id, which is what producers that only record span lineage (`premier emit --span`,
 * native adapters) mean when they name a span. Self references resolve to no parent.
 *
 * Indexes `events` once; resolve against the whole journal, never a filtered subset.
 */
export function parentResolver(events: TraceEvent[]): (event: TraceEvent) => ParentResolution {
  const byId = new Map<string, TraceEvent>();
  const openers = new Map<string, TraceEvent>();
  for (const candidate of events) {
    if (!byId.has(candidate.event_id)) byId.set(candidate.event_id, candidate);
    if (!candidate.span_id) continue;
    const opener = openers.get(candidate.span_id);
    if (!opener || candidate.sequence < opener.sequence) openers.set(candidate.span_id, candidate);
  }
  return (event) => {
    const parentId = event.parent_event_id && event.parent_event_id !== event.event_id ? event.parent_event_id : '';
    if (parentId) {
      let found = byId.get(parentId);
      if (!found) {
        // A producer that put a span id in parent_event_id means the span's opener.
        const named = openers.get(parentId);
        found = named && named.event_id !== event.event_id
          ? named
          : events.find((candidate) => candidate.span_id === parentId && candidate.event_id !== event.event_id);
      }
      if (found) return { found, missing: false, via: 'event', reference: parentId };
    }
    const parentSpan = event.parent_span_id;
    if (parentSpan) {
      const opener = openers.get(parentSpan);
      // Within one span only an earlier event can be the parent, so the span's opener has none.
      const sameSpan = parentSpan === event.span_id;
      if (opener && opener.event_id !== event.event_id && (!sameSpan || opener.sequence < event.sequence)) {
        return { found: opener, missing: false, via: 'span', reference: parentSpan };
      }
      if (!parentId) return sameSpan ? noParent : { found: null, missing: true, via: 'span', reference: parentSpan };
    }
    return parentId ? { found: null, missing: true, via: 'event', reference: parentId } : noParent;
  };
}

/** The lowest-sequence event carrying `spanId`. */
function spanOpener(events: TraceEvent[], spanId: string): TraceEvent | null {
  let opener: TraceEvent | null = null;
  for (const candidate of events) {
    if (candidate.span_id !== spanId) continue;
    if (!opener || candidate.sequence < opener.sequence) opener = candidate;
  }
  return opener;
}

/** Resolve one event's parent; see {@link parentResolver} for the rules. */
export function parentOf(event: TraceEvent, events: TraceEvent[]): ParentResolution {
  return parentResolver(events)(event);
}

/**
 * Events caused by `parentId`: those naming it in parent_event_id, plus those whose parent_span_id is the
 * span this event opened. A child that names a different recorded parent event stays with that parent.
 */
export function childEvents(events: TraceEvent[], parentId: string): TraceEvent[] {
  const parent = events.find((event) => event.event_id === parentId);
  const span = parent?.span_id && spanOpener(events, parent.span_id)?.event_id === parentId ? parent.span_id : '';
  const ids = span ? new Set(events.map((event) => event.event_id)) : null;
  return events.filter((event) => {
    if (event.event_id === parentId) return false;
    if (event.parent_event_id === parentId) return true;
    if (!span || event.parent_span_id !== span) return false;
    const explicit = event.parent_event_id && event.parent_event_id !== event.event_id ? event.parent_event_id : '';
    return !explicit || !ids!.has(explicit);
  });
}

export function correlationPeers(events: TraceEvent[], correlationId: string): TraceEvent[] {
  if (!correlationId) return [];
  return events.filter((event) => event.correlation_id === correlationId);
}

/** Events whose `links` point at this event, by event id or by the span it belongs to. */
export function linkedFrom(events: TraceEvent[], target: TraceEvent): TraceEvent[] {
  return events.filter((event) => event.event_id !== target.event_id
    && event.links.some((id) => id === target.event_id || (target.span_id !== '' && id === target.span_id)));
}

export function resolveRelatedTarget(
  events: TraceEvent[],
  id: string
): { found: TraceEvent | null; missing: boolean } {
  if (!id) return { found: null, missing: false };
  const found = findEventById(events, id) ?? null;
  return { found, missing: !found };
}

export function relatedSummary(event: TraceEvent, events: TraceEvent[]) {
  const parent = parentOf(event, events);
  const children = childEvents(events, event.event_id);
  const peers = event.correlation_id ? correlationPeers(events, event.correlation_id) : [];
  const links: LinkResolution[] = event.links.map((id) => ({ id, ...resolveRelatedTarget(events, id) }));
  return {
    parent,
    children,
    peers: peers.filter((peer) => peer.event_id !== event.event_id),
    links,
    linkedFrom: linkedFrom(events, event),
    missingParent: parent.missing
  };
}
