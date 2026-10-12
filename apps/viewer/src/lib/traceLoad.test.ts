import { describe, expect, it, vi } from 'vitest';
import {
  EVENT_PAGE_SIZE,
  applyTraceComplete,
  eventPages,
  expectedEventCount,
  loadAllEvents,
  mergeLiveEvent,
  mergeLiveEvents,
  resolveSelectedEvent,
  shouldCommitLoad
} from './traceLoad';
import type { TraceEvent, TraceManifest } from './types';

const event = (sequence: number, id = `e${sequence}`): TraceEvent => ({
  event_id: id,
  trace_id: 't1',
  sequence,
  timestamp: '2026-01-01T00:00:00Z',
  kind: 'tool.execution',
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'agent',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: 's',
  parent_span_id: '',
  correlation_id: '',
  status: 'ok',
  duration_ms: 0,
  links: []
});

const manifest = (id: string, ended = true): TraceManifest => ({
  format_version: 1,
  trace_id: id,
  command: ['agent'],
  started_at: '2026-01-01T00:00:00Z',
  ended_at: ended ? '2026-01-01T00:00:01Z' : null,
  exit_code: ended ? 0 : null,
  journal: ended ? { path: 'events/000001.events.pb.zst', sha256: 'abc', event_count: 1 } : null
});

describe('shouldCommitLoad', () => {
  it('accepts only the latest epoch', () => {
    expect(shouldCommitLoad(3, 3)).toBe(true);
    expect(shouldCommitLoad(2, 3)).toBe(false);
  });
});

describe('resolveSelectedEvent', () => {
  it('uses the desired sequence when still in scope', () => {
    const events = [event(1), event(2)];
    const selected = resolveSelectedEvent(events, events, { eventSequence: 2 }, () => events[0]);
    expect(selected?.sequence).toBe(2);
  });

  it('keeps the requested event instead of substituting when it is out of scope', () => {
    const events = [event(1), event(2)];
    const scoped = [events[0]];
    const selected = resolveSelectedEvent(events, scoped, { eventSequence: 2 }, (items) => items[0] ?? null);
    expect(selected?.sequence).toBe(2);
  });

  it('prefers a stable event id over a legacy sequence', () => {
    const events = [event(1, 'stable'), event(2, 'other')];
    const selected = resolveSelectedEvent(events, events, { eventId: 'stable', eventSequence: 2 }, () => events[1]);
    expect(selected?.event_id).toBe('stable');
  });

  it('uses material event when no desired sequence is provided', () => {
    const events = [event(1), event(2)];
    const selected = resolveSelectedEvent(events, events, undefined, (items) => items[1] ?? null);
    expect(selected?.sequence).toBe(2);
  });

  it('returns no selection when a requested event is missing entirely', () => {
    const events = [event(1)];
    const selected = resolveSelectedEvent(events, events, { eventSequence: 99 }, (items) => items[0] ?? null);
    expect(selected).toBeNull();
  });
});

describe('mergeLiveEvent', () => {
  it('appends unique events and ignores duplicates', () => {
    const first = mergeLiveEvent([], event(1));
    expect(first).toHaveLength(1);
    expect(mergeLiveEvent(first, event(1))).toHaveLength(1);
    expect(mergeLiveEvent(first, event(2))).toHaveLength(2);
  });
});

describe('mergeLiveEvents', () => {
  it('appends a burst in one rebuild and dedupes by event_id', () => {
    const base = [event(1)];
    const next = mergeLiveEvents(base, [event(1), event(2), event(3), event(2)]);
    expect(next.map((item) => item.event_id)).toEqual(['e1', 'e2', 'e3']);
  });

  it('returns the same array reference when nothing new arrives', () => {
    const base = [event(1)];
    expect(mergeLiveEvents(base, [])).toBe(base);
    expect(mergeLiveEvents(base, [event(1)])).toBe(base);
  });
});

describe('applyTraceComplete', () => {
  it('merges complete manifest onto the matching live run', () => {
    const live = manifest('t1', false);
    const complete = { ...manifest('t1', true), integrity: 'verified' as const };
    const next = applyTraceComplete(live, complete);
    expect(next?.ended_at).toBeTruthy();
    expect(next?.integrity).toBe('verified');
  });

  it('ignores complete events for a different run', () => {
    const current = manifest('a', false);
    expect(applyTraceComplete(current, manifest('b', true))).toEqual(current);
    expect(applyTraceComplete(null, manifest('a', true))).toBeNull();
  });
});

describe('eventPages', () => {
  const journal = (count: number) => Array.from({ length: count }, (_, index) => event(index + 1));
  const pager = (all: TraceEvent[]) => vi.fn(async (afterSequence: number, limit: number) =>
    all.filter((item) => item.sequence > afterSequence).slice(0, limit));

  it('keeps the page size within the server limit', () => {
    expect(EVENT_PAGE_SIZE).toBeGreaterThan(0);
    expect(EVENT_PAGE_SIZE).toBeLessThanOrEqual(10_000);
  });

  it('walks the journal by sequence cursor and stops at the first short page', async () => {
    const fetchPage = pager(journal(7));
    const pages = [];
    for await (const page of eventPages(fetchPage, 3)) pages.push(page);
    expect(pages.map((page) => page.events.map((item) => item.sequence))).toEqual([[1, 2, 3], [4, 5, 6], [7]]);
    expect(pages.map((page) => page.last)).toEqual([false, false, true]);
    expect(fetchPage.mock.calls).toEqual([[0, 3], [3, 3], [6, 3]]);
  });

  it('reads one empty trailing page when the journal is an exact multiple of the page size', async () => {
    const fetchPage = pager(journal(6));
    const pages = [];
    for await (const page of eventPages(fetchPage, 3)) pages.push(page);
    expect(pages.map((page) => page.events.length)).toEqual([3, 3, 0]);
    expect(pages[2].last).toBe(true);
  });

  it('yields a single last page for a small journal', async () => {
    const fetchPage = pager(journal(2));
    const first = await eventPages(fetchPage, 3).next();
    expect(first.value).toMatchObject({ last: true });
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it('stops instead of looping when a full page does not advance the cursor', async () => {
    const fetchPage = vi.fn(async () => [event(1), event(1, 'again')]);
    const pages = [];
    for await (const page of eventPages(fetchPage, 2)) pages.push(page);
    expect(fetchPage).toHaveBeenCalledTimes(2);
    expect(pages[1].last).toBe(true);
  });

  it('requests nothing further once the load is aborted', async () => {
    const abort = new AbortController();
    const fetchPage = pager(journal(9));
    const pages = eventPages(fetchPage, 3, abort.signal);
    expect((await pages.next()).done).toBe(false);
    abort.abort();
    expect((await pages.next()).done).toBe(true);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it('drops a page that resolves after the abort', async () => {
    const abort = new AbortController();
    const pages = eventPages(async () => { abort.abort(); return [event(1)]; }, 1, abort.signal);
    expect((await pages.next()).done).toBe(true);
  });

  it('propagates a failed page to the caller', async () => {
    const pages = eventPages(async () => { throw new Error('Request failed (500).'); }, 3);
    await expect(pages.next()).rejects.toThrow('Request failed (500).');
  });

  it('collects every page for callers that need the whole journal', async () => {
    const all = journal(8);
    const loaded = await loadAllEvents(pager(all), 3);
    expect(loaded.map((item) => item.sequence)).toEqual(all.map((item) => item.sequence));
  });
});

describe('expectedEventCount', () => {
  it('prefers the summary, falls back to the journal, and is unknown for live runs', () => {
    const finished = manifest('t1');
    expect(expectedEventCount(finished)).toBe(1);
    expect(expectedEventCount({ ...finished, summary: { event_count: 9 } } as TraceManifest)).toBe(9);
    expect(expectedEventCount({ ...finished, journal: null })).toBeNull();
    expect(expectedEventCount(manifest('t1', false))).toBeNull();
  });
});

describe('mergeLiveEvents ordering', () => {
  it('appends an in-order burst without disturbing earlier events', () => {
    const base = [event(1), event(2)];
    const next = mergeLiveEvents(base, [event(3), event(4)]);
    expect(next.map((item) => item.sequence)).toEqual([1, 2, 3, 4]);
    expect(base).toHaveLength(2);
  });

  it('starts an empty journal from the first burst', () => {
    expect(mergeLiveEvents([], [event(1), event(2)]).map((item) => item.sequence)).toEqual([1, 2]);
  });

  it('still dedupes a burst that replays events already held', () => {
    const base = [event(1), event(2), event(3)];
    expect(mergeLiveEvents(base, [event(2), event(3), event(4)]).map((item) => item.sequence)).toEqual([1, 2, 3, 4]);
  });
});
