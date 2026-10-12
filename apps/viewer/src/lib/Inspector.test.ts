import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Inspector from './Inspector.svelte';
import type { TraceEvent } from './types';

const event: TraceEvent = {
  event_id: 'event-1', trace_id: 'trace-1', sequence: 2,
  timestamp: '2026-07-13T12:00:01Z', kind: 'process.stdout', source: 'command',
  payload_json: JSON.stringify({ text: 'captured' }),
  actor_id: 'coder', actor_type: 'subagent', parent_event_id: 'parent-1',
  span_id: 'patch', parent_span_id: 'implementation', correlation_id: 'approval-1',
  status: 'ok', duration_ms: 176, links: ['evidence-1']
};

describe('Inspector', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/');
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) }
    });
  });

  it('summarizes captured evidence once instead of duplicating the primary value', () => {
    render(Inspector, { props: { event } });
    expect(screen.queryByRole('heading', { name: 'Primary evidence' })).not.toBeInTheDocument();
    expect(screen.getAllByText('captured')).toHaveLength(1);
    expect(screen.getByText('coder')).toBeInTheDocument();
    expect(screen.queryByText('Decoded payload')).not.toBeInTheDocument();
  });

  it('survives a JSON null payload without white-screening', async () => {
    const nullPayload = { ...event, payload_json: 'null' };
    render(Inspector, { props: { event: nullPayload } });
    expect(screen.getByText('coder')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: /Data/ }));
    expect(screen.getByText(/null/i)).toBeInTheDocument();
  });

  it('surfaces missing parents instead of silently no-oping', async () => {
    const orphan = { ...event, parent_event_id: 'missing-parent', links: ['also-missing'] };
    render(Inspector, { props: { event: orphan, events: [orphan], onnavigate: vi.fn() } });
    await userEvent.click(screen.getByRole('tab', { name: /Relations/i }));
    expect(screen.getAllByText(/not in journal/i).length).toBeGreaterThan(0);
  });

  it('organizes input, output, effects, authority, and raw evidence', async () => {
    const richEvent = {
      ...event,
      kind: 'tool.call',
      payload_json: JSON.stringify({
        tool_name: 'apply_patch', input: { patch: 'change' }, result: 'done',
        effects: ['src/App.svelte'], approval: 'granted'
      })
    };
    render(Inspector, { props: { event: richEvent } });
    expect(screen.getAllByText('apply_patch').length).toBeGreaterThan(0);

    await userEvent.click(screen.getByRole('tab', { name: /Data/ }));
    expect(screen.getByRole('heading', { name: /Request & input/ })).toBeInTheDocument();
    expect(screen.getByText(/"patch": "change"/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Result/ })).toBeInTheDocument();
    expect(screen.getByText('done')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Effects/ })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Authority & policy/ })).toBeInTheDocument();
    expect(screen.getByText('granted')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('tab', { name: 'Raw' }));
    expect(screen.getByRole('heading', { name: 'Decoded payload' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Event envelope' })).toBeInTheDocument();
  });

  it('treats receipts and expiry as authority evidence and promotes the decision summary', async () => {
    const approvalEvent = {
      ...event,
      kind: 'approval.decision',
      status: 'approved',
      payload_json: JSON.stringify({ receipt: 'apr_01J', expires_after: 'single mutation', scope: 'src/billing.ts' })
    };
    render(Inspector, { props: { event: approvalEvent } });
    expect(screen.getByText(/approved · src\/billing\.ts · receipt apr_01J/)).toBeInTheDocument();
    expect(screen.getAllByText('apr_01J').length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole('tab', { name: /Data/ }));
    expect(screen.getByText('single mutation')).toBeInTheDocument();
    expect(screen.getByText('src/billing.ts')).toBeInTheDocument();
  });

  it('navigates parent and linked evidence through the optional callback', async () => {
    const onnavigate = vi.fn();
    const parent = { ...event, event_id: 'parent-1', sequence: 1, kind: 'agent.turn' };
    const evidence = { ...event, event_id: 'evidence-1', sequence: 3, kind: 'tool.execution' };
    render(Inspector, {
      props: {
        event: { ...event, parent_event_id: 'parent-1', links: ['evidence-1'] },
        events: [parent, event, evidence],
        onnavigate
      }
    });
    await userEvent.click(screen.getByRole('tab', { name: /Relations/ }));
    await userEvent.click(screen.getByRole('button', { name: /parent-1/ }));
    await userEvent.click(screen.getByRole('button', { name: /evidence-1/ }));
    expect(onnavigate).toHaveBeenNthCalledWith(1, 'parent-1');
    expect(onnavigate).toHaveBeenNthCalledWith(2, 'evidence-1');
  });

  it('follows span parents, span children, correlated events, and back-links in one click', async () => {
    const onnavigate = vi.fn();
    const base = { ...event, parent_event_id: '', links: [] as string[], correlation_id: '' };
    const plan = { ...base, event_id: 'plan-1', sequence: 1, kind: 'agent.turn', span_id: 'plan', parent_span_id: '' };
    const tool = { ...base, event_id: 'tool-1', sequence: 2, kind: 'tool.invocation', span_id: 'tool-span', parent_span_id: 'plan', correlation_id: 'call-1' };
    const result = { ...base, event_id: 'result-1', sequence: 3, kind: 'tool.result', span_id: 'result-span', parent_span_id: 'tool-span', correlation_id: 'call-1' };
    const peer = { ...base, event_id: 'peer-1', sequence: 4, kind: 'tool.progress', span_id: 'peer-span', parent_span_id: '', correlation_id: 'call-1' };
    const note = { ...base, event_id: 'note-1', sequence: 5, kind: 'agent.message', span_id: 'note-span', parent_span_id: '', links: ['tool-1'] };
    render(Inspector, { props: { event: tool, events: [plan, tool, result, peer, note], onnavigate } });
    await userEvent.click(screen.getByRole('tab', { name: /Relations/ }));
    expect(screen.queryByText(/not in journal/i)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /plan-1/ }));
    await userEvent.click(screen.getByRole('button', { name: /result-1/ }));
    await userEvent.click(screen.getByRole('button', { name: /peer-1/ }));
    await userEvent.click(screen.getByRole('button', { name: /note-1/ }));
    expect(onnavigate.mock.calls.map(([id]) => id)).toEqual(['plan-1', 'result-1', 'peer-1', 'note-1']);
    expect(screen.getByText('Parent event').closest('div')).toHaveTextContent(/via span plan/);
    expect(screen.getByText('Child event').closest('div')).toHaveTextContent(/tool\.result/);
    expect(screen.getByText('Correlated event').closest('div')).toHaveTextContent(/tool\.progress/);
    expect(screen.getByText('Linked from').closest('div')).toHaveTextContent(/agent\.message/);
  });

  it('flags a parent span that was never recorded', async () => {
    const orphan = { ...event, parent_event_id: '', parent_span_id: 'ghost-span', links: [] as string[] };
    render(Inspector, { props: { event: orphan, events: [orphan], onnavigate: vi.fn() } });
    await userEvent.click(screen.getByRole('tab', { name: /Relations/ }));
    expect(screen.getByText('Parent event').closest('div')).toHaveTextContent(/ghost-span/);
    expect(screen.getByText('Parent event').closest('div')).toHaveTextContent(/not in journal/i);
  });

  it('supports arrow-key navigation across evidence tabs', async () => {
    render(Inspector, { props: { event } });
    const overview = screen.getByRole('tab', { name: 'Overview' });
    overview.focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: /Data/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: /Data/ })).toHaveFocus();
    await userEvent.keyboard('{End}');
    expect(screen.getByRole('tab', { name: 'Raw' })).toHaveFocus();
  });

  it('copies a stable deep link and the captured event JSON', async () => {
    window.history.replaceState({}, '', '/?actor=reviewer&kind=error&from=1&to=2&view=map');
    render(Inspector, { props: { event } });
    await userEvent.click(screen.getByRole('button', { name: 'Copy event link' }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('trace=trace-1'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('event_id=event-1'));
    expect(navigator.clipboard.writeText).not.toHaveBeenCalledWith(expect.stringContaining('event=2'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('view=map'));
    // Investigation scope must survive inspector copy so shared links reopen the same filter window.
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('actor=reviewer'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('kind=error'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('from=1'));

    await userEvent.click(screen.getByRole('button', { name: 'Copy event JSON' }));
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(expect.stringContaining('"event_id": "event-1"'));
  });

  it('uses complementary semantics on desktop and deterministic close actions', async () => {
    const onclose = vi.fn();
    render(Inspector, { props: { event, onclose } });
    expect(screen.getByRole('complementary', { name: 'Event inspector' })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(onclose).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole('button', { name: 'Close inspector' }));
    expect(onclose).toHaveBeenCalledTimes(2);
  });

  it('uses modal semantics when the inspector becomes a responsive overlay', () => {
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: true, addEventListener, removeEventListener })
    });
    render(Inspector, { props: { event, onclose: vi.fn() } });
    expect(screen.getByRole('dialog', { name: 'Event inspector' })).toHaveAttribute('aria-modal', 'true');
  });

  it('provides useful inspector navigation in the compact desktop rail', async () => {
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })
    });
    const onrestore = vi.fn();
    render(Inspector, { props: { event, compact: true, onrestore } });
    expect(screen.getByLabelText('Compact event inspector')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Open Data' }));
    expect(onrestore).toHaveBeenCalledOnce();
  });

  it('separates failure status from event family and treats zero timing as unknown', () => {
    render(Inspector, { props: { event: { ...event, kind: 'tool.error', status: 'error', duration_ms: 0 } } });
    expect(screen.getByText('tool')).toBeInTheDocument();
    expect(screen.getByText('Not captured')).toBeInTheDocument();
  });

  it('makes long evidence explicitly expandable and preserves the complete value', async () => {
    const longValue = `start-${'evidence '.repeat(110)}-finish`;
    render(Inspector, { props: { event: { ...event, payload_json: JSON.stringify({ text: longValue }) } } });
    const toggle = screen.getByRole('button', { name: /Show complete value/ });
    expect(toggle).toHaveTextContent(longValue.length.toLocaleString());
    expect(screen.queryByText(longValue)).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(screen.getByText(longValue)).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
  });

  it('counts only the relations it can open in the Relations badge', async () => {
    // Own span, a parent span, a correlation id and a link, none of which resolves to another event.
    const lonely = { ...event, parent_event_id: '', parent_span_id: 'ghost-span', correlation_id: 'solo', links: ['gone'] };
    const { unmount } = render(Inspector, { props: { event: lonely, events: [lonely], onnavigate: vi.fn() } });
    expect(screen.getByRole('tab', { name: /Relations/ }).querySelector('b')).toBeNull();
    await userEvent.click(screen.getByRole('tab', { name: /Relations/ }));
    // The identifiers are still listed, with what is wrong with them.
    expect(screen.getAllByText('ghost-span').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/not in journal/i).length).toBeGreaterThan(0);
    unmount();

    const parent = { ...event, event_id: 'parent-1', sequence: 1, kind: 'agent.turn', parent_event_id: '', parent_span_id: '', correlation_id: '', links: [] as string[] };
    const child = { ...event, event_id: 'child-1', sequence: 3, parent_event_id: 'event-1', parent_span_id: '', correlation_id: '', links: [] as string[] };
    const current = { ...event, links: ['gone'], correlation_id: '' };
    render(Inspector, { props: { event: current, events: [parent, current, child], onnavigate: vi.fn() } });
    // parent-1 and child-1 open; the span ids and the unresolved link do not count.
    expect(screen.getByRole('tab', { name: /Relations/ }).querySelector('b')).toHaveTextContent('2');
  });

  it('stays on Relations while hopping from one related event to the next', async () => {
    const parent = { ...event, event_id: 'parent-1', sequence: 1, kind: 'agent.turn', parent_event_id: '', links: [] as string[] };
    const current = { ...event, links: [] as string[] };
    const onnavigate = vi.fn();
    const { rerender } = render(Inspector, { props: { event: current, events: [parent, current], onnavigate } });
    await userEvent.click(screen.getByRole('tab', { name: /Relations/ }));
    await userEvent.click(screen.getByRole('button', { name: /parent-1/ }));
    await rerender({ event: parent, events: [parent, current], onnavigate });
    expect(screen.getByRole('tab', { name: /Relations/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('Child event')).toBeInTheDocument();
    // Selecting something else the ordinary way starts at the overview again.
    await rerender({ event: current, events: [parent, current], onnavigate });
    expect(screen.getByRole('tab', { name: /Overview/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('shows a timestamp that is not a date as it was recorded', () => {
    render(Inspector, { props: { event: { ...event, timestamp: 'tuesday-ish' } } });
    expect(screen.getByText('Observed tuesday-ish')).toBeInTheDocument();
    expect(screen.queryByText(/Invalid Date/)).not.toBeInTheDocument();
  });

  it('marks redacted values instead of showing the marker as ordinary content', async () => {
    const redacted = { ...event, payload_json: JSON.stringify({ text: '[REDACTED]', command: 'curl -H "Authorization: [REDACTED]" https://example.test' }) };
    render(Inspector, { props: { event: redacted } });
    await userEvent.click(screen.getByRole('tab', { name: /Data/ }));
    expect(screen.getByText('Redacted by Premier')).toBeInTheDocument();
    expect(screen.getByText('Contains 1 value redacted by Premier')).toBeInTheDocument();
  });

  it('bounds the Raw tab for a multi-megabyte payload and still copies all of it', async () => {
    const big = 'x'.repeat(450_000);
    render(Inspector, { props: { event: { ...event, payload_json: JSON.stringify({ text: big }) } } });
    await userEvent.click(screen.getByRole('tab', { name: /Raw/ }));
    const rendered = () => [...document.querySelectorAll('.raw-section pre')].reduce((sum, pre) => sum + (pre.textContent?.length ?? 0), 0);
    expect(rendered()).toBeLessThan(210_000);
    expect(screen.getByRole('status')).toHaveTextContent('Showing the first 200,000 characters');
    await userEvent.click(screen.getByRole('button', { name: /Copy payload/ }));
    expect(String(vi.mocked(navigator.clipboard.writeText).mock.calls.at(-1)?.[0]).length).toBeGreaterThan(450_000);
    await userEvent.click(screen.getByRole('button', { name: 'Show all' }));
    expect(rendered()).toBeGreaterThan(450_000);
  });
});
