import { describe, expect, it } from 'vitest';
import { childEvents, correlationPeers, findEventById, linkedFrom, parentOf, relatedSummary, resolveRelatedTarget } from './causal';
import type { TraceEvent } from './types';

const event = (overrides: Partial<TraceEvent>): TraceEvent => ({
  event_id: 'e1',
  trace_id: 't1',
  sequence: 1,
  timestamp: '2026-01-01T00:00:00Z',
  kind: 'agent.turn',
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'agent',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: 's1',
  parent_span_id: '',
  correlation_id: '',
  status: 'ok',
  duration_ms: 0,
  links: [],
  ...overrides
});

describe('causal navigation', () => {
  it('finds children by parent_event_id', () => {
    const parent = event({ event_id: 'parent', sequence: 1 });
    const child = event({ event_id: 'child', sequence: 2, parent_event_id: 'parent' });
    expect(childEvents([parent, child], 'parent')).toEqual([child]);
  });

  it('groups correlation peers excluding self', () => {
    const a = event({ event_id: 'a', correlation_id: 'corr-1', sequence: 1 });
    const b = event({ event_id: 'b', correlation_id: 'corr-1', sequence: 2 });
    const c = event({ event_id: 'c', correlation_id: 'other', sequence: 3 });
    expect(correlationPeers([a, b, c], 'corr-1')).toHaveLength(2);
    expect(relatedSummary(a, [a, b, c]).peers.map((peer) => peer.event_id)).toEqual(['b']);
  });

  it('marks missing parents explicitly', () => {
    const orphan = event({ event_id: 'orphan', parent_event_id: 'gone', sequence: 1 });
    const summary = relatedSummary(orphan, [orphan]);
    expect(summary.missingParent).toBe(true);
    expect(resolveRelatedTarget([orphan], 'gone')).toEqual({ found: null, missing: true });
  });

  it('handles empty ids and empty correlation gracefully', () => {
    expect(resolveRelatedTarget([], '')).toEqual({ found: null, missing: false });
    expect(correlationPeers([event({ event_id: 'a' })], '')).toEqual([]);
    const root = event({ event_id: 'root', parent_event_id: '', correlation_id: '' });
    expect(relatedSummary(root, [root]).missingParent).toBe(false);
    expect(relatedSummary(root, [root]).peers).toEqual([]);
  });
});

describe('span, correlation, and link navigation', () => {
  // Shape produced by `premier emit --span/--parent-span`: no parent_event_id anywhere.
  const session = event({ event_id: 'session', sequence: 1, span_id: 'session', kind: 'session.start' });
  const plan = event({ event_id: 'plan-1', sequence: 2, span_id: 'plan', parent_span_id: 'session' });
  const planUpdate = event({ event_id: 'plan-2', sequence: 3, span_id: 'plan', parent_span_id: 'session' });
  const tool = event({ event_id: 'tool-1', sequence: 4, span_id: 'tool-1', parent_span_id: 'plan', kind: 'tool.execution' });
  const model = event({ event_id: 'model-1', sequence: 5, span_id: 'model-1', parent_span_id: 'plan', kind: 'model.response' });
  const journal = [session, plan, planUpdate, tool, model];

  it('resolves a parent through parent_span_id when parent_event_id is empty', () => {
    expect(parentOf(tool, journal)).toEqual({ found: plan, missing: false, via: 'span', reference: 'plan' });
    expect(relatedSummary(tool, journal).parent.found).toBe(plan);
    expect(relatedSummary(tool, journal).missingParent).toBe(false);
    expect(parentOf(session, journal)).toEqual({ found: null, missing: false, via: null, reference: '' });
  });

  it('prefers a recorded parent_event_id and falls back to the span when that id is absent', () => {
    const explicit = event({ event_id: 'explicit', sequence: 6, parent_event_id: 'model-1', parent_span_id: 'plan', span_id: 'x' });
    expect(parentOf(explicit, [...journal, explicit])).toEqual({ found: model, missing: false, via: 'event', reference: 'model-1' });
    // Some producers put a span id in parent_event_id; it still resolves, and never to the event itself.
    const bySpanId = event({ event_id: 'by-span-id', sequence: 8, parent_event_id: 'tool-1-span', span_id: 'tool-1-span' });
    const spanOwner = event({ event_id: 'owner', sequence: 2, span_id: 'tool-1-span' });
    expect(parentOf(bySpanId, [spanOwner, bySpanId])).toEqual({ found: spanOwner, missing: false, via: 'event', reference: 'tool-1-span' });
    expect(parentOf(bySpanId, [bySpanId])).toEqual({ found: null, missing: true, via: 'event', reference: 'tool-1-span' });
    const dangling = event({ event_id: 'dangling', sequence: 7, parent_event_id: 'gone', parent_span_id: 'plan', span_id: 'y' });
    expect(parentOf(dangling, [...journal, dangling])).toEqual({ found: plan, missing: false, via: 'span', reference: 'plan' });
  });

  it('lists span children under the event that opened the span, without duplicates', () => {
    expect(childEvents(journal, 'plan-1').map((child) => child.event_id)).toEqual(['tool-1', 'model-1']);
    expect(relatedSummary(plan, journal).children.map((child) => child.event_id)).toEqual(['tool-1', 'model-1']);
    // Later events of the same span do not repeat the span's children.
    expect(relatedSummary(planUpdate, journal).children).toEqual([]);
    expect(relatedSummary(session, journal).children.map((child) => child.event_id)).toEqual(['plan-1', 'plan-2']);
    const both = event({ event_id: 'both', sequence: 8, parent_event_id: 'plan-1', parent_span_id: 'plan', span_id: 'z' });
    expect(childEvents([...journal, both], 'plan-1').map((child) => child.event_id)).toEqual(['tool-1', 'model-1', 'both']);
    // A child that names a different, present parent event is not claimed by the span.
    const elsewhere = event({ event_id: 'elsewhere', sequence: 9, parent_event_id: 'tool-1', parent_span_id: 'plan', span_id: 'w' });
    expect(childEvents([...journal, elsewhere], 'plan-1').map((child) => child.event_id)).toEqual(['tool-1', 'model-1']);
    expect(childEvents([...journal, elsewhere], 'tool-1').map((child) => child.event_id)).toEqual(['elsewhere']);
    expect(childEvents(journal, 'not-recorded')).toEqual([]);
  });

  it('names the lowest-sequence event of a span as its opener even when the journal is out of order', () => {
    const later = event({ event_id: 'work-2', sequence: 5, span_id: 'work' });
    const opener = event({ event_id: 'work-1', sequence: 2, span_id: 'work' });
    const child = event({ event_id: 'step', sequence: 6, span_id: 'step', parent_span_id: 'work' });
    const shuffled = [later, child, opener];
    expect(parentOf(child, shuffled)).toEqual({ found: opener, missing: false, via: 'span', reference: 'work' });
    // A producer that put the span id in parent_event_id gets the same opener.
    const bySpanId = event({ event_id: 'by-span-id', sequence: 7, span_id: 'other', parent_event_id: 'work' });
    expect(parentOf(bySpanId, [...shuffled, bySpanId])).toEqual({ found: opener, missing: false, via: 'event', reference: 'work' });
    expect(childEvents(shuffled, 'work-1')).toEqual([child]);
    expect(childEvents(shuffled, 'work-2')).toEqual([]);
  });

  it('resolves a repeated event id to the first event recorded with it', () => {
    const original = event({ event_id: 'dup', sequence: 1, span_id: 'first' });
    const repeat = event({ event_id: 'dup', sequence: 2, span_id: 'second' });
    const child = event({ event_id: 'child', sequence: 3, span_id: 'c', parent_event_id: 'dup' });
    const resolved = parentOf(child, [original, repeat, child]);
    expect(resolved).toEqual({ found: original, missing: false, via: 'event', reference: 'dup' });
    expect(resolved.found).toBe(original);
    expect(resolved.found).not.toBe(repeat);
  });

  it('reports a missing parent only when neither reference resolves', () => {
    const orphan = event({ event_id: 'orphan', sequence: 6, parent_span_id: 'never-recorded', span_id: 'o' });
    expect(parentOf(orphan, [...journal, orphan])).toEqual({ found: null, missing: true, via: 'span', reference: 'never-recorded' });
    expect(relatedSummary(orphan, [...journal, orphan]).missingParent).toBe(true);
    const orphanById = event({ event_id: 'orphan-2', sequence: 7, parent_event_id: 'gone', span_id: 'p' });
    expect(parentOf(orphanById, [orphanById])).toEqual({ found: null, missing: true, via: 'event', reference: 'gone' });
  });

  it('survives self references and cycles', () => {
    const selfSpan = event({ event_id: 'self', sequence: 1, span_id: 'loop', parent_span_id: 'loop' });
    expect(parentOf(selfSpan, [selfSpan])).toEqual({ found: null, missing: false, via: null, reference: '' });
    expect(relatedSummary(selfSpan, [selfSpan]).children).toEqual([]);
    const selfId = event({ event_id: 'me', sequence: 1, parent_event_id: 'me', span_id: 'm' });
    expect(parentOf(selfId, [selfId]).found).toBeNull();
    expect(relatedSummary(selfId, [selfId]).children).toEqual([]);
    expect(relatedSummary(selfId, [selfId]).missingParent).toBe(false);

    const a = event({ event_id: 'a', sequence: 1, span_id: 'sa', parent_span_id: 'sb' });
    const b = event({ event_id: 'b', sequence: 2, span_id: 'sb', parent_span_id: 'sa' });
    expect(parentOf(a, [a, b]).found).toBe(b);
    expect(parentOf(b, [a, b]).found).toBe(a);
    expect(relatedSummary(a, [a, b]).children).toEqual([b]);
    expect(relatedSummary(b, [a, b]).children).toEqual([a]);
    // Same span repeated by several events whose parent is that same span: siblings, not ancestors.
    const first = event({ event_id: 'first', sequence: 1, span_id: 'shared', parent_span_id: 'shared' });
    const second = event({ event_id: 'second', sequence: 2, span_id: 'shared', parent_span_id: 'shared' });
    expect(parentOf(second, [first, second]).found).toBe(first);
    expect(parentOf(first, [first, second]).found).toBeNull();
    expect(relatedSummary(first, [first, second]).children).toEqual([second]);
  });

  it('relates events through correlation_id and links in both directions', () => {
    const request = event({ event_id: 'request', sequence: 1, span_id: 'call-1', correlation_id: 'call-1', kind: 'tool.invocation' });
    const result = event({ event_id: 'result', sequence: 2, span_id: 'call-1', correlation_id: 'call-1', kind: 'tool.result' });
    const note = event({ event_id: 'note', sequence: 3, span_id: 'note', links: ['request', 'call-1', 'absent'] });
    const events = [request, result, note];
    expect(relatedSummary(request, events).peers).toEqual([result]);
    expect(relatedSummary(note, events).links).toEqual([
      { id: 'request', found: request, missing: false },
      { id: 'call-1', found: request, missing: false },
      { id: 'absent', found: null, missing: true }
    ]);
    expect(linkedFrom(events, request)).toEqual([note]);
    expect(relatedSummary(request, events).linkedFrom).toEqual([note]);
    expect(linkedFrom(events, result)).toEqual([note]);
    expect(linkedFrom(events, note)).toEqual([]);
    const selfLink = event({ event_id: 'self-link', sequence: 4, span_id: '', links: ['self-link'] });
    expect(linkedFrom([selfLink], selfLink)).toEqual([]);
    expect(findEventById(events, 'call-1')).toBe(request);
    expect(findEventById(events, 'nope')).toBeUndefined();
  });
});
