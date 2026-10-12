import { listKey, type TraceEvent, type TraceManifest } from './types';

export interface TraceLoadResult {
  trace: TraceManifest;
  events: TraceEvent[];
  selectedEvent: TraceEvent | null;
}

export interface EventRequest {
  eventId?: string | null;
  eventSequence?: number | null;
}

/**
 * Atomic load commit: only apply a completed fetch when it still matches the
 * latest requested epoch. Prevents run A events under run B's identity.
 */
export function shouldCommitLoad(requestEpoch: number, currentEpoch: number): boolean {
  return requestEpoch === currentEpoch;
}

export function resolveSelectedEvent(
  events: TraceEvent[],
  scopedEvents: TraceEvent[],
  request: EventRequest | undefined,
  materialEvent: (events: TraceEvent[]) => TraceEvent | null
): TraceEvent | null {
  // Requested identity is a trust boundary: resolve that exact event or none.
  if (request?.eventId) {
    return events.find((event) => event.event_id === request.eventId) ?? null;
  }
  if (request?.eventSequence !== undefined && request.eventSequence !== null) {
    return events.find((event) => event.sequence === request.eventSequence) ?? null;
  }
  return materialEvent(scopedEvents);
}

/**
 * Whether a freshly polled run list differs from the one on screen in anything a row shows: which
 * runs there are, their state, and their counts. A live run's counts change with every event, and
 * a finished run's issue count decides whether its row reads Passed.
 */
export function traceListChanged(current: TraceManifest[], next: TraceManifest[]): boolean {
  if (current.length !== next.length) return true;
  return next.some((item, index) => {
    const shown = current[index];
    return listKey(item) !== listKey(shown)
      || item.trace_id !== shown.trace_id
      || (item.ended_at ?? null) !== (shown.ended_at ?? null)
      || item.exit_code !== shown.exit_code
      || item.integrity !== shown.integrity
      || (item.integrity_detail ?? null) !== (shown.integrity_detail ?? null)
      || item.summary?.event_count !== shown.summary?.event_count
      || item.summary?.issue_count !== shown.summary?.issue_count
      || item.summary?.actor_count !== shown.summary?.actor_count
      || item.summary?.display_name !== shown.summary?.display_name;
  });
}

/** Events requested per page. The server rejects limits above 10,000. */
export const EVENT_PAGE_SIZE = 5_000;

export interface EventLoadProgress {
  loaded: number;
  /** Null when the journal size is not known yet, as for a run that is still recording. */
  total: number | null;
}

export interface EventPage {
  events: TraceEvent[];
  /** True when the journal had nothing beyond this page at the time it was read. */
  last: boolean;
}

export type EventPageFetcher = (afterSequence: number, limit: number) => Promise<TraceEvent[]>;

/**
 * Walk a journal in bounded, sequence-ordered pages. Stops quietly once the
 * signal aborts, so a superseded load never yields another page.
 */
export async function* eventPages(
  fetchPage: EventPageFetcher,
  pageSize = EVENT_PAGE_SIZE,
  signal?: AbortSignal
): AsyncGenerator<EventPage, void, void> {
  let afterSequence = 0;
  while (!signal?.aborted) {
    const events = await fetchPage(afterSequence, pageSize);
    if (signal?.aborted) return;
    let lastSequence = afterSequence;
    for (const event of events) if (event.sequence > lastSequence) lastSequence = event.sequence;
    // A page that does not advance the cursor would repeat forever; treat it as the tail.
    const last = events.length < pageSize || lastSequence <= afterSequence;
    yield { events, last };
    if (last) return;
    afterSequence = lastSequence;
  }
}

/** Collect a whole journal through bounded pages, for callers that need it in one piece. */
export async function loadAllEvents(
  fetchPage: EventPageFetcher,
  pageSize = EVENT_PAGE_SIZE,
  signal?: AbortSignal
): Promise<TraceEvent[]> {
  let all: TraceEvent[] = [];
  for await (const page of eventPages(fetchPage, pageSize, signal)) {
    all = all.length ? all.concat(page.events) : page.events;
  }
  return all;
}

/** Recorded event count for a finished run; live runs have no stable total. */
export function expectedEventCount(trace: TraceManifest): number | null {
  if (!trace.ended_at) return null;
  return trace.summary?.event_count ?? trace.journal?.event_count ?? null;
}

export function mergeLiveEvent(events: TraceEvent[], incoming: TraceEvent): TraceEvent[] {
  if (events.some((event) => event.event_id === incoming.event_id)) return events;
  return [...events, incoming];
}

/** Merge a burst of stream events in one array rebuild (dedupes by event_id). */
export function mergeLiveEvents(events: TraceEvent[], incoming: TraceEvent[]): TraceEvent[] {
  if (!incoming.length) return events;
  // Stream bursts normally continue the journal in order; appending them must not
  // rebuild an id set over every event already loaded.
  let previous = events.length ? events[events.length - 1].sequence : -Infinity;
  let ordered = true;
  for (const event of incoming) {
    if (!(event.sequence > previous)) { ordered = false; break; }
    previous = event.sequence;
  }
  if (ordered) return events.concat(incoming);
  const seen = new Set(events.map((event) => event.event_id));
  const appended: TraceEvent[] = [];
  for (const event of incoming) {
    if (seen.has(event.event_id)) continue;
    seen.add(event.event_id);
    appended.push(event);
  }
  return appended.length ? [...events, ...appended] : events;
}

export function applyTraceComplete(
  current: TraceManifest | null,
  complete: TraceManifest
): TraceManifest | null {
  if (!current || listKey(current) !== listKey(complete)) return current;
  return { ...current, ...complete };
}
