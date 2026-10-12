import { fireEvent, render, screen } from '@testing-library/svelte';
import { expect, it, vi } from 'vitest';
import AgentTopology from './AgentTopology.svelte';
import type { TraceEvent } from './types';

function event(
  sequence: number,
  actor: string,
  type: string,
  kind = 'agent.turn',
  parentEvent = '',
  span = `span-${sequence}`,
  parentSpan = '',
  status = 'ok'
): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence, timestamp: `2026-07-13T12:00:0${sequence}Z`, kind,
    source: 'sdk', payload_json: '{}', actor_id: actor, actor_type: type, parent_event_id: parentEvent,
    span_id: span, parent_span_id: parentSpan, correlation_id: '', status, duration_ms: 0, links: []
  };
}

it('shows labeled actors, roles, evidence counts, issues, and an explanatory legend', () => {
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegate'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1', 'audit'),
    event(3, 'auditor', 'subagent', 'tool.error', 'event-2', 'audit-tool', '', 'error')
  ];
  render(AgentTopology, { props: { events, selectedActor: null, onactor: vi.fn() } });

  expect(screen.getByRole('heading', { name: 'Agent topology' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /coordinator, Agent, 1 event, no issues/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /auditor, Delegated agent, 2 events, 1 issue/ })).toBeInTheDocument();
  expect(screen.getByLabelText('Map scope')).toHaveTextContent('3 supplied events');
  expect(screen.getByLabelText('Map scope')).toHaveTextContent('recorded parent event or parent span');
  expect(screen.getByLabelText('Topology legend')).toHaveTextContent('Blue arrow: parent-to-child event flow');
  expect(screen.getByLabelText('Topology legend')).toHaveTextContent('Dashed arrow: derived from parent spans only');
  expect(screen.getByLabelText('Topology legend')).toHaveTextContent('Dashed node: delegated agent');
});

it('derives cross-actor edges from parent events and parent spans and makes them actionable', async () => {
  const onselect = vi.fn();
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', '', 'audit', 'delegation'),
    event(3, 'auditor', 'subagent', 'tool.execution', 'event-1', 'tool'),
    event(4, 'coordinator', 'agent', 'agent.join', 'event-3', 'join')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn(), onselect } });

  const outbound = screen.getByRole('button', { name: /coordinator to auditor: 2 linked events/i });
  await fireEvent.click(outbound);
  expect(onselect).toHaveBeenCalledWith(events[1]);

  const inbound = screen.getByRole('button', { name: /auditor to coordinator: 1 linked event/i });
  await fireEvent.keyDown(inbound, { key: 'Enter' });
  expect(onselect).toHaveBeenLastCalledWith(events[3]);
});

it('names the event kinds behind an aggregated route and exposes every exact handoff', async () => {
  const onselect = vi.fn();
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1', 'audit'),
    event(3, 'auditor', 'subagent', 'tool.error', 'event-1', 'audit-tool', '', 'error')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn(), onselect } });

  const route = screen.getByRole('button', {
    name: /coordinator to auditor: 2 linked events, agent\.spawn · tool\.error, 1 issue.*representative event tool\.error, sequence 3/i
  });
  await fireEvent.click(route);
  expect(onselect).toHaveBeenLastCalledWith(events[2]);

  const ledger = screen.getByLabelText('Exact handoff evidence');
  expect(ledger).toHaveTextContent('agent.spawn · tool.error');
  expect(ledger).toHaveTextContent('2 events · 1 issue');
  await fireEvent.click(screen.getByText('coordinator', { selector: '.route strong' }));

  const exactSpawn = screen.getByRole('button', { name: /inspect handoff event agent\.spawn, sequence 2/i });
  const exactError = screen.getByRole('button', { name: /inspect handoff event tool\.error, sequence 3/i });
  await fireEvent.click(exactSpawn);
  expect(onselect).toHaveBeenLastCalledWith(events[1]);
  await fireEvent.click(exactError);
  expect(onselect).toHaveBeenLastCalledWith(events[2]);
});

it('selects actors and exposes selection state', async () => {
  const onactor = vi.fn();
  const events = [event(1, 'solo', 'agent')];
  const { rerender } = render(AgentTopology, { props: { events, selectedActor: null, onactor } });
  const actor = screen.getByRole('button', { name: /solo, Agent/ });
  await fireEvent.click(actor);
  expect(onactor).toHaveBeenCalledWith('solo');

  await rerender({ events, selectedActor: 'solo', onactor });
  expect(screen.getByRole('button', { name: /solo, Agent/ })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByText(/one actor, so there are no cross-actor causal links/i)).toBeInTheDocument();
});

it('renders a useful empty state', () => {
  render(AgentTopology, { props: { events: [], onactor: vi.fn() } });
  expect(screen.getByRole('status')).toHaveTextContent('No actors recorded');
  expect(screen.getByRole('status')).toHaveTextContent('parent links');
});

it('provides a pannable, resettable canvas with a minimap', async () => {
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1', 'audit')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn() } });

  const canvas = screen.getByLabelText('Architecture canvas');
  expect(screen.getByLabelText('Architecture minimap')).toBeInTheDocument();
  await fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
  await fireEvent.click(screen.getByRole('button', { name: 'Pan right' }));
  expect(canvas).toHaveAttribute('data-zoom', '1.25');
  expect(canvas).toHaveAttribute('data-pan-x', '-80');

  await fireEvent.pointerDown(canvas, { clientX: 100, clientY: 100, pointerId: 1 });
  await fireEvent.pointerMove(canvas, { clientX: 130, clientY: 125, pointerId: 1 });
  await fireEvent.pointerUp(canvas, { clientX: 130, clientY: 125, pointerId: 1 });
  expect(canvas).toHaveAttribute('data-pan-x', '-50');
  expect(canvas).toHaveAttribute('data-pan-y', '25');

  await fireEvent.click(screen.getByRole('button', { name: 'Reset map view' }));
  expect(canvas).toHaveAttribute('data-zoom', '1');
  expect(canvas).toHaveAttribute('data-pan-x', '0');
  expect(canvas).toHaveAttribute('data-pan-y', '0');
});

it('explains a multi-actor map that has no causal links instead of showing bare nodes', () => {
  // What `premier record` of a provider CLI produces: the recorder's root process and one agent.
  const events = [
    event(1, 'root', 'process', 'session.start'),
    event(2, 'root', 'process', 'process.stdout'),
    event(3, 'claude', 'agent', 'model.response'),
    event(4, 'claude', 'agent', 'tool.call')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn() } });

  const note = screen.getByRole('note', { name: 'Why this map has no connections' });
  expect(note).toHaveTextContent('No causal links were recorded between these 2 actors.');
  expect(note).toHaveTextContent('plain process capture');
  expect(note).toHaveTextContent('parent_event_id');
  expect(screen.getByRole('button', { name: /claude, Agent, 2 events, no issues, no recorded links/ })).toHaveTextContent('No recorded links');
  expect(screen.getByRole('button', { name: /root, Runtime process/ })).toHaveTextContent('No issues recorded');
  expect(screen.queryByText('Healthy')).not.toBeInTheDocument();
  expect(screen.queryByText(/one actor, so there are no/)).not.toBeInTheDocument();
});

it('names the actors a partly linked map leaves unconnected', () => {
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1'),
    event(3, 'bystander', 'agent', 'agent.turn')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn() } });
  expect(screen.getByRole('note')).toHaveTextContent('No causal link recorded for bystander.');
  expect(screen.getByRole('button', { name: /bystander, Agent.*no recorded links/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /auditor, Delegated agent, 1 event, no issues$/ })).toBeInTheDocument();
});

it('distinguishes recorded edges from span-derived ones and says when a role was inferred', () => {
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1', 'audit'),
    event(3, 'helper', 'worker', 'agent.turn', '', 'help', 'delegation')
  ];
  const { container } = render(AgentTopology, { props: { events, onactor: vi.fn() } });
  expect(screen.getByRole('button', { name: /coordinator to auditor: 1 linked event, agent\.spawn, recorded parent events/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /coordinator to helper: 1 linked event, agent\.turn, derived from parent spans/ })).toBeInTheDocument();
  expect(container.querySelectorAll('.edge-line[data-confidence="recorded"]')).toHaveLength(1);
  expect(container.querySelector('.edge-line[data-confidence="derived"]')).toHaveClass('derived');
  const helper = screen.getByRole('button', { name: /helper, Agent, 1 event, no issues, role inferred/ });
  expect(helper).toHaveAttribute('title', expect.stringContaining('Recorded actor_type: worker'));
  expect(screen.getByLabelText('Exact handoff evidence')).toHaveTextContent('derived from spans');
});

it('lists links and shared correlation ids as references that are not causes', async () => {
  const onselect = vi.fn();
  const join = { ...event(3, 'coordinator', 'agent', 'agent.join'), links: ['event-2'] };
  const events = [event(1, 'coordinator', 'agent', 'agent.turn'), event(2, 'auditor', 'subagent', 'agent.turn'), join];
  const { container } = render(AgentTopology, { props: { events, onactor: vi.fn(), onselect } });
  expect(document.querySelector('.summary')).toHaveTextContent('2 actors · 0 causal connections · 1 reference');
  expect(container.querySelector('.edge-line.reference')).toBeInTheDocument();
  const ledger = screen.getByLabelText('Recorded references');
  expect(ledger).toHaveTextContent('links');
  expect(ledger).toHaveTextContent('not a cause');
  await fireEvent.click(screen.getByRole('button', { name: /Inspect referencing event agent\.join, sequence 3/ }));
  expect(onselect).toHaveBeenCalledWith(join);
  // Referenced actors are not called unlinked, and no causal edge was invented.
  expect(screen.queryByText('No recorded links')).not.toBeInTheDocument();
  expect(container.querySelectorAll('.edge-hit')).toHaveLength(0);
});

it('keeps the whole-run structure and only highlights what is in focus', () => {
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1'),
    event(3, 'auditor', 'subagent', 'tool.execution', 'event-2')
  ];
  const { container } = render(AgentTopology, { props: { events, focusEvents: [events[2]], onactor: vi.fn() } });
  expect(document.querySelector('.summary')).toHaveTextContent('2 actors · 1 causal connection');
  expect(screen.getByLabelText('Map scope')).toHaveTextContent('3 supplied events · 1 highlighted');
  expect(container.querySelector('.edge-line')).toHaveClass('muted');
  expect(screen.getByRole('button', { name: /coordinator, Agent/ })).toHaveClass('muted');
});

it('keeps a view the user moved when the stage is resized, until Fit is pressed', async () => {
  const observers: ResizeObserverCallback[] = [];
  vi.stubGlobal('ResizeObserver', class { constructor(callback: ResizeObserverCallback) { observers.push(callback); } observe() {} disconnect() {} });
  try {
    const events = [event(1, 'coordinator', 'agent'), event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1')];
    render(AgentTopology, { props: { events, onactor: vi.fn() } });
    const canvas = screen.getByLabelText('Architecture canvas');
    await fireEvent.click(screen.getByRole('button', { name: 'Pan right' }));
    await fireEvent.wheel(canvas, { deltaY: -300, ctrlKey: true });
    const zoomed = Number(canvas.getAttribute('data-zoom'));
    expect(zoomed).toBeGreaterThan(1);
    observers.forEach((notify) => notify([], {} as ResizeObserver));
    await Promise.resolve();
    expect(canvas).toHaveAttribute('data-zoom', String(zoomed));
    expect(Number(canvas.getAttribute('data-pan-x'))).not.toBe(0);
    await fireEvent.click(screen.getByRole('button', { name: 'Reset map view' }));
    expect(canvas).toHaveAttribute('data-zoom', '1');
    expect(canvas).toHaveAttribute('data-pan-x', '0');
  } finally {
    vi.unstubAllGlobals();
  }
});
