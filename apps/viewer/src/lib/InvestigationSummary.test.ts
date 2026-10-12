import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import InvestigationSummary from './InvestigationSummary.svelte';
import type { TraceEvent, TraceManifest } from './types';

const trace: TraceManifest = {
  format_version: 1, trace_id: 'trace-a', command: ['codex'], started_at: '2026-07-15T12:00:00Z',
  ended_at: '2026-07-15T12:00:04Z', exit_code: 1, journal: null
};

const event = (sequence: number, kind: string, overrides: Partial<TraceEvent> = {}): TraceEvent => ({
  event_id: `event-${sequence}`, trace_id: 'trace-a', sequence, timestamp: `2026-07-15T12:00:0${sequence}Z`, kind,
  source: 'sdk', payload_json: '{}', actor_id: 'coordinator', actor_type: 'agent', parent_event_id: '',
  span_id: `span-${sequence}`, parent_span_id: '', correlation_id: 'job', status: 'ok', duration_ms: 0, links: [], ...overrides
});

describe('InvestigationSummary', () => {
  it('renders ranked investigation evidence and selects the recommended event', async () => {
    const onselect = vi.fn();
    const events = [
      event(1, 'tool.execution', { duration_ms: 2300, payload_json: '{"tool":"deploy"}' }),
      event(2, 'tool.error', { parent_event_id: 'event-1', status: 'error', payload_json: '{"tool":"deploy","error":"denied"}' })
    ];
    render(InvestigationSummary, { props: { trace, events, onselect } });

    expect(screen.getByRole('region', { name: 'Investigation summary' })).toBeInTheDocument();
    expect(screen.getByText('Likely cause')).toBeInTheDocument();
    expect(screen.getByText('Failure chain')).toBeInTheDocument();
    expect(screen.getByText('Slow & expensive')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: /inspect recommended event/i }));
    expect(onselect).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'event-2' }));
  });

  it('labels a terminal-only failure as an outcome instead of a likely cause', () => {
    const exit = event(1, 'process.exit', { actor_id: 'root', actor_type: 'process', status: 'error', payload_json: '{"exit_code":2}' });
    render(InvestigationSummary, { props: { trace: { ...trace, exit_code: 2, termination: { kind: 'exit', exit_code: 2 } }, events: [exit] } });
    expect(screen.queryByText('Likely cause')).not.toBeInTheDocument();
    expect(screen.getByText('Outcome · cause not recorded')).toBeInTheDocument();
    expect(screen.getByText('low confidence')).toBeInTheDocument();
    expect(screen.getByText('Process exited with status 2')).toBeInTheDocument();
    expect(screen.getByText('Exit cause is missing')).toBeInTheDocument();
  });

  it('provides a compact truthful empty state for an active trace', () => {
    render(InvestigationSummary, { props: { trace: { ...trace, ended_at: null, exit_code: null, integrity: 'live' }, events: [] } });
    expect(screen.getByText('Waiting for evidence')).toBeInTheDocument();
    expect(screen.getByText('No events captured')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /inspect recommended event/i })).not.toBeInTheDocument();
  });

  it('lets compact viewports reveal and collapse the supporting evidence', async () => {
    render(InvestigationSummary, { props: { trace, events: [event(1, 'tool.error', { status: 'error' })] } });
    const toggle = screen.getByRole('button', { name: /show investigation details/i });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(toggle).toHaveAccessibleName(/hide investigation details/i);
  });

  it('counts evidence gaps while collapsed and opens the event a recorder diagnostic is about', async () => {
    const onselect = vi.fn();
    const diagnostics = [
      { severity: 'warning' as const, code: 'missing_lifecycle_result', message: 'agent.spawn has no matching agent.result', event_id: 'event-1', sequence: 1 },
      { severity: 'warning' as const, code: 'missing_lifecycle_result', message: 'agent.spawn has no matching agent.result', event_id: 'event-2', sequence: 2 }
    ];
    const events = [event(1, 'agent.spawn'), event(2, 'agent.spawn'), event(3, 'process.exit', { payload_json: '{"exit_code":0}' })];
    render(InvestigationSummary, { props: { trace: { ...trace, exit_code: 0, diagnostics }, events, onselect } });

    // Shown on the header before Details is opened.
    expect(screen.getByRole('button', { name: /show investigation details/i })).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getByTestId('investigation-gap-count')).toHaveTextContent('2 gaps');
    const rows = screen.getAllByRole('button', { name: /^Inspect event #\d+ for: Recorded lifecycle evidence is incomplete/ });
    expect(rows).toHaveLength(2);
    await fireEvent.click(rows[1]);
    expect(onselect).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'event-2' }));
  });
});
