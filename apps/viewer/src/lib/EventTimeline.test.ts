import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import EventTimeline from './EventTimeline.svelte';
import type { TraceEvent } from './types';

const event: TraceEvent = {
  event_id: 'event-1', trace_id: 'trace-1', sequence: 2,
  timestamp: '2026-07-13T12:00:01Z', kind: 'process.stdout', source: 'command',
  payload_json: JSON.stringify({ text: 'test output\n' }),
  actor_id: 'researcher', actor_type: 'subagent', parent_event_id: 'parent-1',
  span_id: 'search', parent_span_id: 'research', correlation_id: '', status: 'ok',
  duration_ms: 42, links: []
};

it('summarizes output and selects an event', async () => {
  const onselect = vi.fn();
  render(EventTimeline, { props: { events: [event], selectedSequence: null, onselect } });
  const option = screen.getByRole('option', { name: /process.stdout/i });
  expect(option).toHaveTextContent('test output');
  await userEvent.click(option);
  expect(onselect).toHaveBeenCalledWith(event);
});

it('shows complete actor names without a causal graph', () => {
  render(EventTimeline, { props: { events: [event], selectedSequence: null, onselect: vi.fn() } });
  expect(screen.getByText('researcher')).toBeInTheDocument();
  expect(screen.queryByText('RES')).not.toBeInTheDocument();
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  expect(screen.getByText('sub-agent')).toBeInTheDocument();
});

it('uses roving focus and arrow keys to inspect adjacent evidence', async () => {
  const onselect = vi.fn();
  const next = { ...event, event_id: 'event-2', sequence: 3, kind: 'tool.execution', payload_json: JSON.stringify({ tool: 'rg', matches: 7 }) };
  render(EventTimeline, { props: { events: [event, next], selectedSequence: event.sequence, onselect } });
  const options = screen.getAllByRole('option');
  options[0].focus();
  await userEvent.keyboard('{ArrowDown}');
  expect(onselect).toHaveBeenLastCalledWith(next);
  expect(options[1]).toHaveFocus();
  expect(options[1]).toHaveAccessibleName(expect.stringContaining('rg · 7 matches'));
});

it('does not put an empty-state message inside a listbox', () => {
  render(EventTimeline, { props: { events: [], selectedSequence: null, onselect: vi.fn() } });
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('No matching evidence');
});

it('discloses long summaries without replacing row selection', async () => {
  const onselect = vi.fn();
  const longText = `Beginning ${'full captured evidence '.repeat(12)}ending`;
  const verbose = { ...event, payload_json: JSON.stringify({ text: longText }) };
  render(EventTimeline, { props: { events: [verbose], selectedSequence: null, onselect } });
  const toggle = screen.getByRole('button', { name: 'Read full summary' });
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await userEvent.click(toggle);
  expect(toggle).toHaveAttribute('aria-expanded', 'true');
  expect(screen.getByText(longText)).toHaveClass('expanded');
  expect(onselect).not.toHaveBeenCalled();
});

it('bounds the rendered DOM for a ten-thousand-event trace', () => {
  const events = Array.from({ length: 10_000 }, (_, index): TraceEvent => ({
    ...event,
    event_id: `event-${index}`,
    sequence: index,
    kind: 'tool.execution',
    actor_id: `actor-${index % 6}`,
    payload_json: JSON.stringify({ tool: 'verify', index })
  }));
  render(EventTimeline, { props: { events, selectedSequence: null, onselect: vi.fn() } });
  expect(screen.getByText(/windowed rendering/)).toBeInTheDocument();
  expect(screen.getAllByRole('option').length).toBeLessThan(100);
});

it('allows mouse scrolling away from an early selection in a virtualized timeline', async () => {
  const events = Array.from({ length: 500 }, (_, index): TraceEvent => ({
    ...event,
    event_id: `event-${index}`,
    sequence: index,
    kind: 'tool.execution',
    actor_id: `actor-${index % 6}`,
    payload_json: JSON.stringify({ tool: 'verify', index })
  }));
  const { container } = render(EventTimeline, {
    props: { events, selectedSequence: 0, onselect: vi.fn() }
  });
  const scroller = container.querySelector('.timeline-scroll') as HTMLDivElement;
  expect(scroller).toBeTruthy();
  Object.defineProperty(scroller, 'clientHeight', { configurable: true, value: 400 });
  scroller.scrollTop = 0;
  scroller.dispatchEvent(new Event('scroll'));

  scroller.scrollTop = 12_000;
  scroller.dispatchEvent(new Event('scroll'));
  await Promise.resolve();

  // Selection stays early, but the viewport must not snap scrollTop back to 0.
  expect(scroller.scrollTop).toBe(12_000);
  expect(screen.getByText(/windowed rendering/)).toBeInTheDocument();
});

const synthetic = (count: number): TraceEvent[] => Array.from({ length: count }, (_, index): TraceEvent => ({
  ...event,
  event_id: `event-${index}`,
  sequence: index + 1,
  kind: 'tool.execution',
  actor_id: `actor-${index % 6}`,
  parent_event_id: '',
  parent_span_id: '',
  span_id: `span-${index}`,
  payload_json: JSON.stringify({ tool: 'verify', index })
}));

function sizeScroller(container: HTMLElement, height = 640) {
  const scroller = container.querySelector('.timeline-scroll') as HTMLDivElement;
  Object.defineProperty(scroller, 'clientHeight', { configurable: true, value: height });
  return scroller;
}

const renderedPositions = () => screen.getAllByRole('option').map((option) => Number(option.getAttribute('aria-posinset')));

it('keeps the DOM bounded for a 50k-event trace wherever the list is scrolled', async () => {
  const events = synthetic(50_000);
  const { container } = render(EventTimeline, { props: { events, selectedSequence: null, onselect: vi.fn() } });
  const scroller = sizeScroller(container);
  expect(screen.getAllByRole('option').length).toBeLessThan(60);
  expect(renderedPositions()[0]).toBe(1);

  for (const top of [64 * 1_000, 64 * 25_000, 64 * 49_999]) {
    scroller.scrollTop = top;
    await fireEvent.scroll(scroller);
    const rows = screen.getAllByRole('option');
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length).toBeLessThan(60);
    expect(renderedPositions()).toContain(top / 64 + 1);
  }
  // Every row advertises its place in the full set, not in the rendered window.
  expect(screen.getAllByRole('option')[0]).toHaveAttribute('aria-setsize', '50000');
  // Spacers stand in for the rows that are not rendered, so the scrollbar spans the whole trace.
  const spacers = [...container.querySelectorAll<HTMLElement>('.virtual-spacer')];
  const spacerHeight = spacers.reduce((sum, spacer) => sum + parseFloat(spacer.style.height), 0);
  expect(spacerHeight + screen.getAllByRole('option').length * 64).toBe(50_000 * 64);
});

it('scrolls a deep-linked late event into the window and marks it selected', async () => {
  const events = synthetic(50_000);
  const { container } = render(EventTimeline, { props: { events, selectedSequence: 49_990, onselect: vi.fn() } });
  const scroller = container.querySelector('.timeline-scroll') as HTMLDivElement;
  const selected = await waitFor(() => {
    const row = container.querySelector('[role="option"][aria-selected="true"]');
    expect(row).toBeTruthy();
    return row as HTMLElement;
  });
  expect(selected).toHaveAttribute('data-event-id', 'event-49989');
  expect(selected).toHaveAttribute('tabindex', '0');
  expect(scroller.scrollTop).toBeGreaterThan(64 * 49_000);
  expect(screen.getAllByRole('option').length).toBeLessThan(60);
});

it('selects a late event by click and reveals a selection that arrives with a later page', async () => {
  const events = synthetic(50_000);
  const onselect = vi.fn();
  const { container, rerender } = render(EventTimeline, {
    props: { events: events.slice(0, 5_000), selectedSequence: 40_000, onselect, loading: { loaded: 5_000, total: 50_000 } }
  });
  const scroller = sizeScroller(container);
  // The linked event has not been loaded yet: nothing is selected and the list stays put.
  expect(screen.getByRole('status')).toHaveTextContent('Loading 5,000 of 50,000 events');
  expect(container.querySelector('[aria-selected="true"]')).toBeNull();
  expect(scroller.scrollTop).toBe(0);
  expect(screen.getAllByRole('option').filter((option) => option.tabIndex === 0)).toHaveLength(1);

  await rerender({ events, selectedSequence: 40_000, onselect, loading: null });
  await waitFor(() => expect(container.querySelector('[aria-selected="true"]')).toHaveAttribute('data-event-id', 'event-39999'));
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.getAllByRole('option').length).toBeLessThan(60);

  const neighbour = container.querySelector('[data-event-id="event-40001"]') as HTMLElement;
  const before = scroller.scrollTop;
  await userEvent.click(neighbour);
  expect(onselect).toHaveBeenLastCalledWith(events[40_001]);
  await rerender({ events, selectedSequence: 40_002, onselect, loading: null });
  // A visible row is selected in place; the list does not jump under the pointer.
  expect(scroller.scrollTop).toBe(before);
  expect(container.querySelector('[aria-selected="true"]')).toHaveAttribute('data-event-id', 'event-40001');
});

it('keeps keyboard navigation working across a windowed 50k-event trace', async () => {
  const events = synthetic(50_000);
  const onselect = vi.fn();
  const { container, rerender } = render(EventTimeline, { props: { events, selectedSequence: 1, onselect } });
  const scroller = sizeScroller(container);
  const focusedId = () => (document.activeElement as HTMLElement | null)?.getAttribute('data-event-id');

  (container.querySelector('[data-event-id="event-0"]') as HTMLElement).focus();
  await userEvent.keyboard('{End}');
  expect(onselect).toHaveBeenLastCalledWith(events[49_999]);
  await waitFor(() => expect(focusedId()).toBe('event-49999'));
  await rerender({ events, selectedSequence: 50_000, onselect });
  expect(scroller.scrollTop).toBeGreaterThan(64 * 49_900);
  expect(screen.getAllByRole('option').length).toBeLessThan(60);

  const settled = scroller.scrollTop;
  await userEvent.keyboard('{ArrowUp}');
  expect(onselect).toHaveBeenLastCalledWith(events[49_998]);
  await waitFor(() => expect(focusedId()).toBe('event-49998'));
  await rerender({ events, selectedSequence: 49_999, onselect });
  // Stepping to a row that is already visible does not move the viewport.
  expect(scroller.scrollTop).toBe(settled);

  await userEvent.keyboard('{Home}');
  expect(onselect).toHaveBeenLastCalledWith(events[0]);
  await waitFor(() => expect(focusedId()).toBe('event-0'));
  expect(scroller.scrollTop).toBe(0);
});

it('re-windows when filters or search narrow a large trace', async () => {
  const events = synthetic(50_000);
  const { container, rerender } = render(EventTimeline, { props: { events, selectedSequence: 30_001, onselect: vi.fn() } });
  sizeScroller(container);
  await waitFor(() => expect(container.querySelector('[aria-selected="true"]')).toBeTruthy());

  // One actor's events, as the filter bar would pass them: the selection keeps its row.
  const filtered = events.filter((item) => item.actor_id === 'actor-0');
  await rerender({ events: filtered, selectedSequence: 30_001, onselect: vi.fn() });
  expect(screen.getByText(new RegExp(`^${filtered.length} events`))).toBeInTheDocument();
  expect(screen.getAllByRole('option').length).toBeLessThan(60);
  expect(container.querySelector('[aria-selected="true"]')).toHaveAttribute('data-event-id', 'event-30000');

  await rerender({ events: filtered.slice(0, 3), selectedSequence: 1, onselect: vi.fn() });
  expect(screen.getAllByRole('option')).toHaveLength(3);
  await rerender({ events: [], selectedSequence: null, onselect: vi.fn() });
  expect(screen.getByText('No matching evidence')).toBeInTheDocument();
});
