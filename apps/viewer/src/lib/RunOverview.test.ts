import { render, screen } from '@testing-library/svelte';
import { expect, it } from 'vitest';
import RunOverview from './RunOverview.svelte';
import type { TraceEvent, TraceManifest } from './types';

const trace: TraceManifest = {
  format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '', exit_code: 0, journal: null
};

function event(sequence: number, id: string, type: string, kind: string, status = 'ok'): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence, timestamp: '2026-07-13T12:00:01Z', kind,
    source: 'sdk', payload_json: '{}', actor_id: id, actor_type: type, parent_event_id: '', span_id: `span-${sequence}`,
    parent_span_id: '', correlation_id: '', status, duration_ms: 0, links: []
  };
}

it('shows truthful actor roles and semantic run health in compact header chips', () => {
  const events = [
    event(1, 'root', 'process', 'process.stdout'),
    event(2, 'coordinator', 'agent', 'agent.turn'),
    event(3, 'researcher', 'subagent', 'model.response'),
    event(4, 'brad', 'human', 'approval.decision'),
    event(5, 'reviewer', 'subagent', 'tool.error', 'error')
  ];
  render(RunOverview, { props: { trace, events, compact: true } });
  expect(screen.getByText('Needs attention')).toBeInTheDocument();
  expect(screen.getByLabelText('Run overview')).toHaveTextContent('Actors');
  expect(screen.getByLabelText('Run overview')).toHaveTextContent('5');
  expect(screen.getByText('1 issue')).toBeInTheDocument();
});

it('surfaces an integrity chip for invalid journals instead of Passed', () => {
  render(RunOverview, {
    props: {
      compact: true,
      trace: {
        ...trace,
        integrity: 'invalid',
        integrity_detail: 'journal digest mismatch',
        exit_code: 0
      },
      events: [event(1, 'root', 'process', 'process.exit')]
    }
  });
  expect(screen.getByText('Unverified')).toBeInTheDocument();
  expect(screen.getByText('Integrity failed')).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveAttribute('title', 'journal digest mismatch');
});

it('tells the reader an abandoned recording needs premier recover', () => {
  const abandoned: TraceManifest = {
    ...trace, ended_at: null, exit_code: null, integrity: 'abandoned',
    integrity_detail: 'The recorder is no longer running. Run `premier recover /traces/a.atrace` to finalize this trace.'
  };
  const events = [event(1, 'root', 'process', 'process.stdout')];
  const compact = render(RunOverview, { props: { compact: true, trace: abandoned, events } });
  expect(screen.getByText('Abandoned')).toBeInTheDocument();
  expect(screen.queryByText('Running')).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('Abandoned — run premier recover');
  expect(screen.getByRole('status')).toHaveAttribute('title', abandoned.integrity_detail);
  compact.unmount();

  render(RunOverview, { props: { trace: abandoned, events } });
  expect(screen.getByRole('status')).toHaveTextContent('Abandoned — run premier recover');
  expect(screen.getByRole('status')).toHaveTextContent('premier recover /traces/a.atrace');
});

it('states whether a verified trace is signed, and by which key, in the evidence detail', () => {
  const events = [event(1, 'root', 'process', 'process.exit')];
  const signed = render(RunOverview, {
    props: { trace: { ...trace, integrity: 'verified', integrity_protection: 'signed', integrity_signer: 'sha256:abc123' }, events }
  });
  expect(signed.container.querySelector('.evidence small')).toHaveTextContent('signed by sha256:abc123');
  signed.unmount();
  const unsigned = render(RunOverview, {
    props: { trace: { ...trace, integrity: 'verified', integrity_protection: 'sealed' }, events }
  });
  expect(unsigned.container.querySelector('.evidence small')).toHaveTextContent('unsigned, self-consistent only');
});
