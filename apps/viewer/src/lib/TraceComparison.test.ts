import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import TraceComparison from './TraceComparison.svelte';
import type { TraceEvent, TraceManifest } from './types';

const manifest = (traceId: string, overrides: Partial<TraceManifest> = {}): TraceManifest => ({
  format_version: 1, trace_id: traceId, name: traceId === 'base' ? 'Baseline run' : 'Current run', command: ['codex'],
  started_at: '2026-07-15T12:00:00Z', ended_at: '2026-07-15T12:00:04Z', exit_code: 0, journal: null, ...overrides
});

const event = (traceId: string, sequence: number, kind: string, overrides: Partial<TraceEvent> = {}): TraceEvent => ({
  event_id: `${traceId}-${sequence}`, trace_id: traceId, sequence, timestamp: `2026-07-15T12:00:0${sequence}Z`, kind,
  source: 'sdk', payload_json: '{}', actor_id: 'coordinator', actor_type: 'agent', parent_event_id: '',
  span_id: `${traceId}-span-${sequence}`, parent_span_id: '', correlation_id: `${traceId}-job`, status: 'ok', duration_ms: 10, links: [], ...overrides
});

describe('TraceComparison', () => {
  it('renders run health, semantic counts, field changes, and operational deltas', async () => {
    const onselectCurrent = vi.fn();
    const baselineEvents = [
      event('base', 1, 'model.response', { duration_ms: 200, payload_json: '{"model":"gpt-5","response":"old","usage":{"total_tokens":100},"cost_usd":0.1}' }),
      event('base', 2, 'tool.execution', { payload_json: '{"tool":"grep"}' })
    ];
    const currentEvents = [
      event('current', 1, 'model.response', { duration_ms: 500, status: 'warning', payload_json: '{"model":"gpt-5.1","response":"new","usage":{"total_tokens":160},"cost_usd":0.18}' }),
      event('current', 2, 'tool.execution', { payload_json: '{"tool":"browser"}' })
    ];
    render(TraceComparison, { props: { baseline: manifest('base'), current: manifest('current'), baselineEvents, currentEvents, onselectCurrent } });

    expect(screen.getByRole('region', { name: 'Trace comparison' })).toBeInTheDocument();
    expect(screen.getByText('Baseline run')).toBeInTheDocument();
    expect(screen.getByText('Current run')).toBeInTheDocument();
    expect(screen.getByLabelText('Changed events')).toHaveTextContent('1');
    expect(screen.getByLabelText('Added events')).toHaveTextContent('1');
    expect(screen.getByLabelText('Removed events')).toHaveTextContent('1');

    const changed = screen.getByTestId('comparison-changed-0');
    expect(within(changed).getByText('payload.model')).toBeInTheDocument();
    expect(within(changed).getByText('+300 ms')).toBeInTheDocument();
    expect(within(changed).getByText('+60 tok')).toBeInTheDocument();
    expect(within(changed).getByText('+$0.08')).toBeInTheDocument();
    await fireEvent.click(within(changed).getByRole('button', { name: /inspect current event/i }));
    expect(onselectCurrent).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'current-1' }));
  });

  it('renders issue metrics truthfully for each side', () => {
    const baselineEvents = [event('base', 1, 'tool.error', { status: 'error' })];
    const currentEvents = [event('current', 1, 'tool.execution')];
    render(TraceComparison, {
      props: {
        baseline: manifest('base', { exit_code: 1 }), current: manifest('current'), baselineEvents, currentEvents
      }
    });
    const baselineCard = screen.getByLabelText('Baseline run summary');
    expect(baselineCard).toHaveTextContent('Failed');
    expect(baselineCard).toHaveTextContent('1 issue');
    const currentCard = screen.getByLabelText('Current run summary');
    expect(currentCard).toHaveTextContent('Passed');
    expect(currentCard).toHaveTextContent('0 issues');
  });

  it('shows a useful no-difference state when regenerated ids are the only changes', () => {
    render(TraceComparison, {
      props: {
        baseline: manifest('base'), current: manifest('current'),
        baselineEvents: [event('base', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"same"}' })],
        currentEvents: [event('current', 9, 'tool.execution', { payload_json: '{"tool":"search","query":"same"}' })]
      }
    });
    expect(screen.getByText('No meaningful differences')).toBeInTheDocument();
    expect(screen.getByText(/in the same order; generated ids are ignored/i)).toBeInTheDocument();
    expect(screen.queryByTestId('comparison-first-divergence')).not.toBeInTheDocument();
  });

  it('handles empty traces without offering dead navigation', () => {
    render(TraceComparison, { props: { baseline: manifest('base'), current: manifest('current'), baselineEvents: [], currentEvents: [] } });
    expect(screen.getByText('No evidence to compare')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /inspect current event/i })).not.toBeInTheDocument();
  });

  it('lists differences in trace order with both positions, and opens baseline-side events', async () => {
    const onselectBaseline = vi.fn();
    const onselectCurrent = vi.fn();
    const baselineEvents = [
      event('base', 1, 'agent.turn'),
      event('base', 2, 'tool.execution', { payload_json: '{"tool":"lint"}' }),
      event('base', 3, 'model.response', { payload_json: '{"response":"old"}' })
    ];
    const currentEvents = [
      event('current', 1, 'agent.turn'),
      event('current', 2, 'model.response', { payload_json: '{"response":"new"}' }),
      event('current', 3, 'tool.execution', { payload_json: '{"tool":"deploy"}' })
    ];
    render(TraceComparison, { props: { baseline: manifest('base'), current: manifest('current'), baselineEvents, currentEvents, onselectBaseline, onselectCurrent } });

    const rows = within(screen.getByLabelText('Meaningful differences')).getAllByRole('article');
    // Trace order, not grouped by status: the removed lint call comes before the changed response.
    expect(rows.map((row) => row.dataset.status)).toEqual(['removed', 'changed', 'added']);
    expect(rows[0]).toHaveTextContent('baseline #2');
    expect(rows[1]).toHaveTextContent('baseline #3 → current #2');
    expect(rows[2]).toHaveTextContent('current #3');
    // The first row is the first divergence the header names.
    expect(screen.getByTestId('comparison-first-divergence')).toHaveTextContent('removed · tool.execution');
    expect(screen.getByTestId('comparison-first-divergence')).toHaveTextContent('baseline #2');
    // Both positions, readably separated, when the first divergence exists on both sides.
    expect(rows[1]).toHaveTextContent(/baseline #3 → current #2/);

    // A removed event exists only in the baseline, and can be opened there.
    expect(within(rows[0]).queryByRole('button', { name: /inspect current event/i })).not.toBeInTheDocument();
    await fireEvent.click(within(rows[0]).getByRole('button', { name: /open baseline event #2 tool\.execution/i }));
    expect(onselectBaseline).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'base-2' }));
    // A changed event can be opened on either side.
    await fireEvent.click(within(rows[1]).getByRole('button', { name: /open baseline event #3/i }));
    expect(onselectBaseline).toHaveBeenLastCalledWith(expect.objectContaining({ event_id: 'base-3' }));
    await fireEvent.click(within(rows[1]).getByRole('button', { name: /inspect current event/i }));
    expect(onselectCurrent).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'current-2' }));
    // An added event has no baseline side.
    expect(within(rows[2]).queryByRole('button', { name: /open baseline event/i })).not.toBeInTheDocument();
  });

  it('shows every field change and whole values on request', async () => {
    const long = 'x'.repeat(200);
    const fields = (suffix: string) => Object.fromEntries(Array.from({ length: 8 }, (_, index) => [`field_${index}`, `${suffix}-${index}`]));
    const baselineEvents = [event('base', 1, 'tool.execution', { payload_json: JSON.stringify({ tool: 'build', ...fields('old'), log: `${long}-old` }) })];
    const currentEvents = [event('current', 1, 'tool.execution', { payload_json: JSON.stringify({ tool: 'build', ...fields('new'), log: `${long}-new` }) })];
    render(TraceComparison, { props: { baseline: manifest('base'), current: manifest('current'), baselineEvents, currentEvents } });
    const row = screen.getByTestId('comparison-changed-0');
    expect(within(row).queryByText('payload.log')).not.toBeInTheDocument();
    expect(within(row).queryByText(`${long}-new`)).not.toBeInTheDocument();
    const more = within(row).getByRole('button', { name: 'Show all 9 field changes' });
    expect(more).toHaveAttribute('aria-expanded', 'false');
    await fireEvent.click(more);
    expect(within(row).getByText('payload.log')).toBeInTheDocument();
    // Whole values, not an 80-character excerpt.
    expect(within(row).getByText(`${long}-old`)).toBeInTheDocument();
    expect(within(row).getByText(`${long}-new`)).toBeInTheDocument();
    await fireEvent.click(within(row).getByRole('button', { name: 'Show less' }));
    expect(within(row).queryByText('payload.log')).not.toBeInTheDocument();
  });

  it('renders a long list of differences a page at a time', async () => {
    const currentEvents = Array.from({ length: 450 }, (_, index) => event('current', index + 1, 'tool.execution', { payload_json: `{"tool":"step-${index}"}` }));
    render(TraceComparison, { props: { baseline: manifest('base'), current: manifest('current'), baselineEvents: [], currentEvents } });
    const list = screen.getByLabelText('Meaningful differences');
    expect(list).toHaveTextContent('450 differences');
    expect(within(list).getAllByRole('article')).toHaveLength(200);
    await fireEvent.click(within(list).getByRole('button', { name: 'Show 200 more of 250 remaining differences' }));
    expect(within(list).getAllByRole('article')).toHaveLength(400);
    await fireEvent.click(within(list).getByRole('button', { name: 'Show 50 more of 50 remaining differences' }));
    expect(within(list).getAllByRole('article')).toHaveLength(450);
    expect(within(list).queryByRole('button', { name: /remaining differences/ })).not.toBeInTheDocument();
  });
});
