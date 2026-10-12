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
 * The event that opened a span: the lowest-sequence event carrying that span_id. Producers that only
 * record span lineage (`premier emit --span`, native adapters) mean this event when they name a span.
 */
function spanOpener(events: TraceEvent[], spanId: string, exclude?: TraceEvent): TraceEvent | null {
  let opener: TraceEvent | null = null;
  for (const candidate of events) {
    if (candidate.span_id !== spanId || candidate.event_id === exclude?.event_id) continue;
    if (!opener || candidate.sequence < opener.sequence) opener = candidate;
  }
  return opener;
}

/**
 * Resolve an event's parent. A recorded parent_event_id wins; otherwise (or when that id is not in the
 * journal) the parent is the event that opened parent_span_id. Self references resolve to no parent.
 */
export function parentOf(event: TraceEvent, events: TraceEvent[]): ParentResolution {
  const parentId = event.parent_event_id && event.parent_event_id !== event.event_id ? event.parent_event_id : '';
  if (parentId) {
    const found = events.find((candidate) => candidate.event_id === parentId)
      ?? events.find((candidate) => candidate.span_id === parentId && candidate.event_id !== event.event_id);
    if (found) return { found, missing: false, via: 'event', reference: parentId };
  }
  const parentSpan = event.parent_span_id;
  if (parentSpan) {
    const opener = spanOpener(events, parentSpan, event);
    // Within one span only an earlier event can be the parent, so the span's opener has none.
    const sameSpan = parentSpan === event.span_id;
    if (opener && (!sameSpan || opener.sequence < event.sequence)) {
      return { found: opener, missing: false, via: 'span', reference: parentSpan };
    }
    if (!parentId) return sameSpan ? noParent : { found: null, missing: true, via: 'span', reference: parentSpan };
  }
  return parentId ? { found: null, missing: true, via: 'event', reference: parentId } : noParent;
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
