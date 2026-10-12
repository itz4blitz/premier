import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compareTraces } from './semanticCompare';
import type { TraceEvent } from './types';

const event = (traceId: string, sequence: number, kind: string, overrides: Partial<TraceEvent> = {}): TraceEvent => ({
  event_id: `${traceId}-${sequence}`,
  trace_id: traceId,
  sequence,
  timestamp: `2026-07-15T12:00:0${sequence}.000Z`,
  kind,
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'coordinator',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: `${traceId}-span-${sequence}`,
  parent_span_id: '',
  correlation_id: `${traceId}-generated-id`,
  status: 'ok',
  duration_ms: 10,
  links: [],
  ...overrides
});

describe('compareTraces', () => {
  it('aligns semantically equivalent events despite regenerated ids and correlations', () => {
    const baseline = [event('a', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"alpha"}' })];
    const current = [event('b', 9, 'tool.execution', { payload_json: '{"tool":"search","query":"alpha"}' })];
    const result = compareTraces(baseline, current);
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toMatchObject({ status: 'unchanged', baseline: { event_id: 'a-1' }, current: { event_id: 'b-9' } });
  });

  it('reports curated payload, status, duration, token, and cost deltas on aligned calls', () => {
    const baseline = [event('a', 1, 'model.response', { duration_ms: 200, payload_json: '{"model":"gpt-5","response":"old","usage":{"total_tokens":100},"cost_usd":0.1}' })];
    const current = [event('b', 1, 'model.response', { status: 'warning', duration_ms: 500, payload_json: '{"model":"gpt-5.1","response":"new","usage":{"total_tokens":160},"cost_usd":0.18}' })];
    const item = compareTraces(baseline, current).items[0];
    expect(item.status).toBe('changed');
    expect(item.deltas.durationMs).toEqual({ before: 200, after: 500, delta: 300 });
    expect(item.deltas.totalTokens).toEqual({ before: 100, after: 160, delta: 60 });
    expect(item.deltas.costUsd).toEqual({ before: 0.1, after: 0.18, delta: 0.08 });
    expect(item.changes.map((change) => change.field)).toEqual(expect.arrayContaining(['status', 'payload.model', 'payload.response']));
  });

  it('classifies different tool identities as removed and added instead of a false change', () => {
    const baseline = [event('a', 1, 'tool.execution', { payload_json: '{"tool":"grep"}' })];
    const current = [event('b', 1, 'tool.execution', { payload_json: '{"tool":"browser"}' })];
    const result = compareTraces(baseline, current);
    expect(result.counts).toMatchObject({ added: 1, removed: 1, changed: 0, unchanged: 0 });
    expect(result.items.map((item) => item.status)).toEqual(['removed', 'added']);
  });

  it('aligns repeated semantic calls in order and preserves insertion order', () => {
    const baseline = [
      event('a', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"one"}' }),
      event('a', 2, 'tool.execution', { payload_json: '{"tool":"search","query":"two"}' })
    ];
    const current = [
      event('b', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"one"}' }),
      event('b', 2, 'tool.execution', { payload_json: '{"tool":"search","query":"changed"}' }),
      event('b', 3, 'tool.execution', { payload_json: '{"tool":"search","query":"three"}' })
    ];
    const result = compareTraces(baseline, current);
    expect(result.items.map((item) => item.status)).toEqual(['unchanged', 'changed', 'added']);
    expect(result.items[1].changes).toContainEqual(expect.objectContaining({ field: 'payload.query', before: 'two', after: 'changed' }));
  });

  it('reports a duration difference as a change, as premier diff does', () => {
    const baseline = [event('a', 1, 'tool.execution', { duration_ms: 100, payload_json: '{"tool":"search"}' })];
    const current = [event('b', 1, 'tool.execution', { duration_ms: 240, payload_json: '{"tool":"search"}' })];
    const item = compareTraces(baseline, current).items[0];
    expect(item.status).toBe('changed');
    expect(item.changes).toEqual([{ field: 'duration_ms', before: 100, after: 240 }]);
    expect(item.deltas.durationMs).toEqual({ before: 100, after: 240, delta: 140 });
  });

  it('names the first divergence and reports an event that only moved', () => {
    const order = (traceId: string, tools: string[]) => tools.map((tool, index) => event(traceId, index + 1, 'tool.execution', { duration_ms: 0, payload_json: JSON.stringify({ tool }) }));
    const result = compareTraces(order('a', ['read', 'search', 'grep', 'write']), order('b', ['read', 'grep', 'search', 'write']));
    expect(result.counts).toEqual({ added: 0, removed: 0, changed: 0, moved: 1, unchanged: 3 });
    expect(result.alignment).toBe('ordered');
    expect(result.firstDivergence?.index).toBe(2);
    expect(result.firstDivergence?.item).toMatchObject({ status: 'moved', baseline: { sequence: 2 }, current: { sequence: 3 }, changes: [] });
    expect(compareTraces(order('a', ['read']), order('b', ['read'])).firstDivergence).toBeNull();
  });
});

interface FixtureEvent { sequence: number; kind: string; payload?: unknown; [field: string]: unknown }
interface FixtureCase {
  name: string;
  baseline: FixtureEvent[];
  current: FixtureEvent[];
  expected: {
    counts: Record<string, number>;
    first_divergence: { index: number; key: string; status: string } | null;
    items: Array<{ key: string; status: string; baseline_sequence: number | null; current_sequence: number | null; fields: string[] }>;
  };
}

/** The defaults `premier diff`'s own test applies to the same file. */
function fixtureEvent(side: string, fields: FixtureEvent): TraceEvent {
  const { payload, ...rest } = fields;
  return {
    event_id: `${side}-${fields.sequence}`,
    trace_id: side,
    timestamp: '2026-07-15T12:00:00Z',
    source: 'sdk',
    actor_id: 'agent',
    actor_type: 'agent',
    parent_event_id: '',
    span_id: '',
    parent_span_id: '',
    correlation_id: '',
    status: 'ok',
    duration_ms: 0,
    links: [],
    ...rest,
    payload_json: JSON.stringify(payload ?? {})
  } as TraceEvent;
}

describe('compareTraces and premier diff', () => {
  const fixture = JSON.parse(readFileSync(
    resolve(__dirname, '../../../../crates/premier-cli/tests/fixtures/diff/semantic-diff-cases.json'),
    'utf8'
  )) as { cases: FixtureCase[] };

  it('has the shared cases to run', () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(7);
  });

  it.each(fixture.cases.map((item) => [item.name, item] as const))('agree on: %s', (_name, shared) => {
    const result = compareTraces(
      shared.baseline.map((item) => fixtureEvent('baseline', item)),
      shared.current.map((item) => fixtureEvent('current', item))
    );
    expect(result.items.map((item) => ({
      key: item.key,
      status: item.status,
      baseline_sequence: item.baseline?.sequence ?? null,
      current_sequence: item.current?.sequence ?? null,
      fields: item.changes.map((change) => change.field)
    }))).toEqual(shared.expected.items);
    expect(result.counts).toEqual(shared.expected.counts);
    expect(result.firstDivergence && {
      index: result.firstDivergence.index,
      key: result.firstDivergence.item.key,
      status: result.firstDivergence.item.status
    }).toEqual(shared.expected.first_divergence);
    expect(result.alignment).toBe('ordered');
  });
});
