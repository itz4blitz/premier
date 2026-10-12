import { render, screen } from '@testing-library/svelte';
import { expect, it, vi } from 'vitest';
import ModelUsage from './ModelUsage.svelte';
import type { TraceEvent } from './types';

function call(sequence: number, payload: Record<string, unknown>): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-usage', sequence, timestamp: '2026-07-14T12:00:00Z',
    kind: 'model.response', source: 'test', payload_json: JSON.stringify(payload), actor_id: 'researcher',
    actor_type: 'agent', parent_event_id: '', span_id: `span-${sequence}`, parent_span_id: '',
    correlation_id: '', status: 'ok', duration_ms: 100, links: []
  };
}

it('says how many calls a partial total covers, and shows unreported usage as unknown, not zero', () => {
  render(ModelUsage, {
    props: {
      events: [
        call(1, { model: 'gpt-test', usage: { input_tokens: 100, output_tokens: 20 }, cost_usd: 0.01 }),
        call(2, { model: 'gpt-test', usage: { input_tokens: 50, output_tokens: 10 } }),
        call(3, { model: 'gpt-test' })
      ],
      onselect: vi.fn()
    }
  });
  const totals = screen.getByLabelText('Model usage totals');
  expect(totals).toHaveTextContent('Total tokens180');
  expect(screen.getByTestId('usage-token-coverage')).toHaveTextContent('2 of 3 calls reported tokens');
  expect(screen.getByTestId('usage-cost-coverage')).toHaveTextContent('1 of 3 calls reported a cost');
  // No call reported a cache or reasoning breakdown: a dash, never 0.
  expect(totals).toHaveTextContent('Cache—');
  expect(totals).toHaveTextContent('Reasoning—');
});

it('reports complete coverage plainly and a wholly unreported figure as unknown', () => {
  render(ModelUsage, { props: { events: [call(1, { model: 'gpt-test', usage: { input_tokens: 5, output_tokens: 5 } })], onselect: vi.fn() } });
  expect(screen.getByTestId('usage-token-coverage')).toHaveTextContent('1 recorded call');
  expect(screen.getByTestId('usage-cost-coverage')).toHaveTextContent('No call reported a cost');
  expect(screen.getByLabelText('Model usage totals')).toHaveTextContent('Recorded cost—');
});
