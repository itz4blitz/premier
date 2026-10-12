import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App.svelte';
import type { TraceEvent, TraceManifest } from './lib/types';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  window.history.replaceState({}, '', '/');
});

const trace: TraceManifest = {
  format_version: 1, trace_id: 'trace-1', name: 'Investigation', command: ['agent'],
  started_at: '2026-01-01T00:00:00Z', ended_at: '2026-01-01T00:00:01Z', exit_code: 0,
  journal: { path: 'events/000001.events.pb.zst', sha256: 'abc', event_count: 2 },
  integrity: 'verified',
  artifact: 'investigation.atrace'
};

const events: TraceEvent[] = [
  { event_id: 'event-1', trace_id: 'trace-1', sequence: 1, timestamp: '2026-01-01T00:00:00Z', kind: 'session.start', source: 'premier', payload_json: '{}', actor_id: 'root', actor_type: 'process', parent_event_id: '', span_id: 'session', parent_span_id: '', correlation_id: '', status: 'running', duration_ms: 0, links: [] },
  { event_id: 'event-2', trace_id: 'trace-1', sequence: 2, timestamp: '2026-01-01T00:00:01Z', kind: 'tool.execution', source: 'sdk', payload_json: '{"tool":"rg","matches":4}', actor_id: 'agent', actor_type: 'agent', parent_event_id: 'event-1', span_id: 'tool', parent_span_id: 'session', correlation_id: '', status: 'ok', duration_ms: 12, links: [] }
];

function mockWorkspace(traces: TraceManifest[] = [trace], eventMap: Record<string, TraceEvent[]> = { 'trace-1': events }) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/traces')) {
      return new Response(JSON.stringify(traces), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    const eventsMatch = url.match(/\/api\/traces\/([^/]+)\/events$/);
    if (eventsMatch) {
      const id = decodeURIComponent(eventsMatch[1]);
      return new Response(JSON.stringify(eventMap[id] ?? []), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    const detailMatch = url.match(/\/api\/traces\/([^/]+)$/);
    if (detailMatch) {
      const id = decodeURIComponent(detailMatch[1]);
      const found = traces.find((item) => item.trace_id === id) ?? { ...trace, trace_id: id };
      return new Response(JSON.stringify(found), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });
}

it('renders a workspace-shaped loading state', () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(() => {}));
  render(App);
  expect(screen.getByLabelText('Loading trace workspace')).toBeInTheDocument();
  expect(document.querySelector('.loading-metrics')).toBeInTheDocument();
  expect(document.querySelector('.loading-time')).toBeInTheDocument();
  expect(document.querySelector('.skeleton-density')).toBeInTheDocument();
  expect(document.querySelector('.loading-runs')).toBeInTheDocument();
  expect(document.querySelector('.loading-events')).toBeInTheDocument();
  expect(document.querySelector('.loading-detail')).toBeInTheDocument();
});

it('shows a useful empty state', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
  render(App);
  expect(await screen.findByText('No traces yet')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Refresh runs' })).toBeInTheDocument();
  expect(screen.getByText('premier demo')).toBeInTheDocument();
  expect(screen.getByText('premier record -- npm test')).toBeInTheDocument();
  expect(document.body.textContent).toMatch(/premier emit/);
  expect(document.body.textContent).toMatch(/@premierstudio\/trace/);
});

it('does not substitute another run when a shared trace id is missing', async () => {
  window.history.replaceState({}, '', '/?trace=missing-trace');
  mockWorkspace([trace]);
  render(App);
  expect(await screen.findByText('Trace not found')).toBeInTheDocument();
  expect(screen.getByText(/missing-trace was not found/)).toBeInTheDocument();
});

it('opens a stable event-id deep link and canonicalizes legacy sequence links', async () => {
  window.history.replaceState({}, '', '/?trace=trace-1&event_id=event-1');
  mockWorkspace();
  const { unmount } = render(App);
  await waitFor(() => expect(screen.getByRole('complementary', { name: 'Event inspector' })).toHaveTextContent('session start'));
  expect(new URL(window.location.href).searchParams.get('event_id')).toBe('event-1');
  expect(new URL(window.location.href).searchParams.has('event')).toBe(false);
  unmount();

  window.history.replaceState({}, '', '/?trace=trace-1&event=2');
  render(App);
  await waitFor(() => expect(new URL(window.location.href).searchParams.get('event_id')).toBe('event-2'));
  expect(new URL(window.location.href).searchParams.has('event')).toBe(false);
});

it('surfaces a missing linked event without selecting unrelated evidence and offers recovery', async () => {
  window.history.replaceState({}, '', '/?trace=trace-1&event_id=event-gone');
  mockWorkspace();
  render(App);
  expect(await screen.findByText('Linked event not found')).toBeInTheDocument();
  expect(screen.getByText(/event-gone is not present/)).toBeInTheDocument();
  expect(screen.queryByRole('complementary', { name: 'Event inspector' })).not.toBeInTheDocument();
  await fireEvent.click(screen.getByRole('button', { name: 'Open run overview' }));
  expect(screen.queryByText('Linked event not found')).not.toBeInTheDocument();
  expect(new URL(window.location.href).searchParams.has('event_id')).toBe(false);
  expect(new URL(window.location.href).searchParams.has('event')).toBe(false);
});

it('surfaces authentication failures', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }));
  render(App);
  await waitFor(() => expect(screen.getByText('Viewer unavailable')).toBeInTheDocument());
  expect(screen.getByText('Authentication is required.')).toBeInTheDocument();
});

it('opens on the first material event instead of session metadata', async () => {
  mockWorkspace();
  render(App);
  await waitFor(() => expect(new URL(window.location.href).searchParams.get('event_id')).toBe('event-2'));
  expect(new URL(window.location.href).searchParams.has('event')).toBe(false);
});

it('renders the complete run name and trace identity in the header', async () => {
  const descriptiveTrace = {
    ...trace,
    trace_id: '019f5e1e-343f-7693-afd5-2c71140e1ef1',
    name: 'Multi-agent investigation with a deliberately descriptive run name that must remain readable'
  };
  mockWorkspace(
    [descriptiveTrace],
    { [descriptiveTrace.trace_id]: events.map((event) => ({ ...event, trace_id: descriptiveTrace.trace_id })) }
  );
  render(App);
  const context = screen.getByLabelText('Current run');
  await waitFor(() => expect(context).toHaveTextContent(descriptiveTrace.name));
  expect(context).toHaveTextContent(descriptiveTrace.name);
  expect(context).toHaveTextContent(descriptiveTrace.trace_id);
  expect(context).not.toHaveTextContent('019f5e1e-343f…');
  expect(screen.getByLabelText(`Trace ID ${descriptiveTrace.trace_id}`)).toHaveTextContent(descriptiveTrace.trace_id);
});

it('disables empty categories instead of presenting a dead filter', async () => {
  mockWorkspace();
  render(App);
  expect(await screen.findByRole('button', { name: 'issues' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'models' })).toBeDisabled();
  expect(new URL(window.location.href).searchParams.has('kind')).toBe(false);
});

it('keeps secondary investigation tools in More instead of crowding the header', async () => {
  const baseline = { ...trace, trace_id: 'trace-2', name: 'Baseline', artifact: 'baseline.atrace' };
  mockWorkspace([trace, baseline], {
    'trace-1': events,
    'trace-2': events.map((event) => ({ ...event, trace_id: 'trace-2', event_id: `baseline-${event.event_id}` }))
  });
  render(App);
  await screen.findByRole('button', { name: 'Ask AI' });
  expect(screen.queryByRole('button', { name: 'Compare runs' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Slideshow' })).not.toBeInTheDocument();

  await fireEvent.click(screen.getByRole('button', { name: 'More' }));
  const compare = screen.getByRole('menuitem', { name: /Compare runs/ });
  expect(compare).toBeInTheDocument();
  expect(screen.getByRole('menuitem', { name: /Slideshow/ })).toBeInTheDocument();
  await fireEvent.click(compare);
  expect(await screen.findByRole('dialog', { name: /Compare runs/ })).toBeInTheDocument();
  expect(await screen.findByRole('region', { name: 'Trace comparison' })).toBeInTheDocument();
});

it('restores and persists every desktop workspace dimension', async () => {
  localStorage.setItem('premier.viewer.workspace.v1', JSON.stringify({ leftWidth: 312, rightWidth: 440, timeNavigatorHeight: 236, leftCollapsed: false, rightCollapsed: true }));
  mockWorkspace();
  render(App);
  const separator = await screen.findByRole('separator', { name: 'Resize trace list' });
  expect(separator).toHaveAttribute('aria-valuenow', '312');
  expect(screen.getByRole('separator', { name: 'Resize run activity' })).toHaveAttribute('aria-valuenow', '236');
  expect(screen.getByRole('button', { name: 'Restore event inspector' })).toBeInTheDocument();
  await fireEvent.keyDown(separator, { key: 'ArrowRight' });
  await fireEvent.keyDown(screen.getByRole('separator', { name: 'Resize run activity' }), { key: 'ArrowDown' });
  expect(JSON.parse(localStorage.getItem('premier.viewer.workspace.v1') ?? '{}')).toMatchObject({ leftWidth: 324, timeNavigatorHeight: 248, rightCollapsed: true });
});

it('ignores malformed persisted workspace state', async () => {
  localStorage.setItem('premier.viewer.workspace.v1', '{broken');
  mockWorkspace();
  render(App);
  expect(await screen.findByRole('separator', { name: 'Resize trace list' })).toHaveAttribute('aria-valuenow', '260');
});

it('repaints from the session cache on hard refresh without a skeleton flash', async () => {
  const cachedTrace: TraceManifest = {
    ...trace,
    trace_id: 'cached-trace',
    name: 'Cached investigation'
  };
  const cachedEvents = events.map((event) => ({ ...event, trace_id: 'cached-trace', event_id: `cached-${event.event_id}` }));
  sessionStorage.setItem('premier.viewer.session.v1', JSON.stringify({
    version: 1,
    savedAt: Date.now(),
    traces: [cachedTrace],
    selectedTrace: cachedTrace,
    events: cachedEvents,
    selectedSequence: 2
  }));

  let releaseNetwork: (() => void) | undefined;
  const networkGate = new Promise<void>((resolve) => { releaseNetwork = resolve; });
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/traces')) {
      await networkGate;
      return new Response(JSON.stringify([cachedTrace]), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/events')) {
      await networkGate;
      return new Response(JSON.stringify(cachedEvents), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/api/traces/cached-trace')) {
      await networkGate;
      return new Response(JSON.stringify(cachedTrace), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });

  window.history.replaceState({}, '', '/?trace=cached-trace&event=2&view=analytics');
  render(App);

  expect(document.querySelector('.loading-shell')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Cached investigation');
  expect(screen.getByRole('button', { name: 'Analytics' })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getAllByText('tool.execution').length).toBeGreaterThan(0);
  // Warm revalidate: progress may show, but evidence should not dim.
  expect(document.querySelector('.run-shell')).not.toHaveClass('content-stale');

  releaseNetwork?.();
  await waitFor(() => expect(document.querySelector('.run-shell')).not.toHaveClass('trace-loading'));
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Cached investigation');
});

it('keeps the previous run painted while the next load is in flight', async () => {
  const current: TraceManifest = { ...trace, trace_id: 'current', name: 'Current run', artifact: 'current.atrace' };
  const next: TraceManifest = { ...trace, trace_id: 'next', name: 'Next run', artifact: 'next.atrace' };
  const currentEvents: TraceEvent[] = events.map((event) => ({ ...event, trace_id: 'current', event_id: `current-${event.event_id}` }));
  const nextEvents: TraceEvent[] = [
    { ...events[0], trace_id: 'next', event_id: 'next-1', kind: 'session.start' },
    { ...events[1], trace_id: 'next', event_id: 'next-2', kind: 'agent.turn', payload_json: '{"goal":"next"}' }
  ];

  let releaseNext: (() => void) | undefined;
  const nextGate = new Promise<void>((resolve) => { releaseNext = resolve; });

  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/traces')) {
      return new Response(JSON.stringify([current, next]), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/api/traces/current/events')) {
      return new Response(JSON.stringify(currentEvents), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/api/traces/next/events')) {
      await nextGate;
      return new Response(JSON.stringify(nextEvents), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.endsWith('/api/traces/current')) {
      return new Response(JSON.stringify(current), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.endsWith('/api/traces/next')) {
      return new Response(JSON.stringify(next), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });

  window.history.replaceState({}, '', '/?trace=current');
  render(App);
  await waitFor(() => expect(screen.getAllByText('tool.execution').length).toBeGreaterThan(0));
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Current run');

  await fireEvent.click(screen.getByRole('button', { name: /Next run/ }));
  expect(document.querySelector('.run-shell')).toHaveClass('trace-loading');
  expect(screen.getByText('Loading run evidence…')).toBeInTheDocument();
  // Stale-while-revalidate: previous evidence stays painted instead of flashing empty.
  expect(screen.getAllByText('tool.execution').length).toBeGreaterThan(0);
  expect(screen.queryByText('No matching evidence')).not.toBeInTheDocument();

  releaseNext?.();
  await waitFor(() => expect(screen.getAllByText('agent.turn').length).toBeGreaterThan(0));
  expect(document.querySelector('.run-shell')).not.toHaveClass('trace-loading');
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Next run');
  expect(screen.queryByText('tool.execution')).not.toBeInTheDocument();
});

it('never attributes a slower previous load to a newer selected run', async () => {
  const slow: TraceManifest = { ...trace, trace_id: 'slow', name: 'Slow run', artifact: 'slow.atrace' };
  const fast: TraceManifest = { ...trace, trace_id: 'fast', name: 'Fast run', artifact: 'fast.atrace' };
  const slowEvents: TraceEvent[] = events.map((event) => ({ ...event, trace_id: 'slow', event_id: `slow-${event.event_id}` }));
  const fastEvents: TraceEvent[] = [
    { ...events[0], trace_id: 'fast', event_id: 'fast-1', kind: 'session.start' },
    { ...events[1], trace_id: 'fast', event_id: 'fast-2', kind: 'agent.turn', payload_json: '{"goal":"fast"}' }
  ];

  let releaseSlow: (() => void) | undefined;
  const slowGate = new Promise<void>((resolve) => { releaseSlow = resolve; });

  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/traces')) {
      return new Response(JSON.stringify([fast, slow]), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/api/traces/slow/events')) {
      await slowGate;
      return new Response(JSON.stringify(slowEvents), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/api/traces/fast/events')) {
      return new Response(JSON.stringify(fastEvents), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.endsWith('/api/traces/slow')) {
      return new Response(JSON.stringify(slow), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.endsWith('/api/traces/fast')) {
      return new Response(JSON.stringify(fast), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });

  window.history.replaceState({}, '', '/?trace=fast');
  render(App);
  await waitFor(() => expect(screen.getAllByText('agent.turn').length).toBeGreaterThan(0));
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Fast run');

  // Start a slow load, then immediately re-select the fast run so the slow response is stale.
  await fireEvent.click(screen.getByRole('button', { name: /Slow run/ }));
  await fireEvent.click(screen.getByRole('button', { name: /Fast run/ }));
  await waitFor(() => expect(screen.getAllByText('agent.turn').length).toBeGreaterThan(0));
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Fast run');

  releaseSlow?.();
  await new Promise((resolve) => setTimeout(resolve, 40));
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Fast run');
  expect(screen.queryByText('tool.execution')).not.toBeInTheDocument();
  expect(screen.getAllByText('agent.turn').length).toBeGreaterThan(0);
});

it('shows unverified outcome for integrity-invalid traces', async () => {
  const invalid: TraceManifest = {
    ...trace,
    integrity: 'invalid',
    integrity_detail: 'journal digest mismatch',
    name: 'Tampered'
  };
  mockWorkspace([invalid]);
  render(App);
  expect(await screen.findAllByText('Unverified')).not.toHaveLength(0);
  expect(screen.getByText('Integrity failed')).toBeInTheDocument();
});

it('leaves the empty state when Refresh runs finds a first recording', async () => {
  let available: TraceManifest[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/traces')) return new Response(JSON.stringify(available), { status: 200 });
    if (url.endsWith('/events')) return new Response(JSON.stringify(events), { status: 200 });
    return new Response(JSON.stringify(trace), { status: 200 });
  });
  const errors: unknown[] = [];
  const onError = (event: ErrorEvent) => { errors.push(event.error ?? event.message); event.preventDefault(); };
  const onRejection = (event: PromiseRejectionEvent) => { errors.push(event.reason); event.preventDefault(); };
  window.addEventListener('error', onError);
  window.addEventListener('unhandledrejection', onRejection);
  try {
    render(App);
    expect(await screen.findByText('No traces yet')).toBeInTheDocument();
    available = [trace];
    await fireEvent.click(screen.getByRole('button', { name: 'Refresh runs' }));
    await waitFor(() => expect(document.querySelector('.run-shell')).toBeInTheDocument());
    await waitFor(() => expect(screen.getAllByText('tool.execution').length).toBeGreaterThan(0));
    expect(screen.queryByText('No traces yet')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Investigation summary')).toBeInTheDocument();
    expect(new URL(window.location.href).searchParams.get('trace')).toBe('trace-1');
    expect(errors).toEqual([]);
  } finally {
    window.removeEventListener('error', onError);
    window.removeEventListener('unhandledrejection', onRejection);
  }
});

it('opens the first recording when the background poll finds it on the empty state', async () => {
  let available: TraceManifest[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/api/traces')) return new Response(JSON.stringify(available), { status: 200 });
    if (url.endsWith('/events')) return new Response(JSON.stringify(events), { status: 200 });
    return new Response(JSON.stringify(trace), { status: 200 });
  });
  const polls: Array<() => void> = [];
  const realSetInterval = window.setInterval.bind(window);
  vi.spyOn(window, 'setInterval').mockImplementation(((handler: TimerHandler, timeout?: number, ...rest: unknown[]) => {
    if (timeout === 4000 && typeof handler === 'function') {
      polls.push(handler as () => void);
      return 0;
    }
    return realSetInterval(handler, timeout, ...rest);
  }) as typeof window.setInterval);
  render(App);
  expect(await screen.findByText('No traces yet')).toBeInTheDocument();
  await waitFor(() => expect(polls).toHaveLength(1));
  available = [trace];
  polls[0]();
  await waitFor(() => expect(screen.getAllByText('tool.execution').length).toBeGreaterThan(0));
  expect(screen.queryByText('No traces yet')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Current run')).toHaveTextContent('Investigation');
});

it('recovers from a missing shared trace by opening the latest available run', async () => {
  window.history.replaceState({}, '', '/?trace=missing-trace&event=4');
  mockWorkspace([trace]);
  render(App);
  expect(await screen.findByText('Trace not found')).toBeInTheDocument();
  await fireEvent.click(screen.getByRole('button', { name: 'Open the latest available run' }));
  await waitFor(() => expect(screen.getAllByText('tool.execution').length).toBeGreaterThan(0));
  expect(screen.queryByText('Trace not found')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Investigation summary')).toBeInTheDocument();
  expect(new URL(window.location.href).searchParams.get('trace')).toBe('trace-1');
});

it('exports token usage intact, masks credentials, and labels the file honestly', async () => {
  const usageEvents: TraceEvent[] = [
    events[0],
    { ...events[1], kind: 'model.response', payload_json: JSON.stringify({ model: 'gpt-5.2', apiKey: 'sk-live-EXPORT1', usage: { input_tokens: 1296, output_tokens: 546, total_tokens: 1842 } }) },
    { ...events[1], event_id: 'event-3', sequence: 3, kind: 'process.stdout', payload_json: JSON.stringify({ text: '{"apiKey":"sk-live-STDOUT1","ok":true}\n' }) }
  ];
  const unverified: TraceManifest = { ...trace, integrity: 'invalid', integrity_detail: 'journal digest mismatch' };
  mockWorkspace([unverified], { 'trace-1': usageEvents });
  const blobs: Blob[] = [];
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn((blob: Blob) => { blobs.push(blob); return 'blob:export'; }) });
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

  render(App);
  await screen.findByRole('button', { name: 'Ask AI' });
  await waitFor(() => expect(screen.getAllByText('model.response').length).toBeGreaterThan(0));
  await fireEvent.click(screen.getByRole('button', { name: 'More' }));
  await fireEvent.click(screen.getByRole('menuitem', { name: /Export safe JSON/ }));

  expect(click).toHaveBeenCalledTimes(1);
  expect(blobs).toHaveLength(1);
  const text = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blobs[0]);
  });
  expect(text).not.toContain('sk-live-EXPORT1');
  expect(text).not.toContain('sk-live-STDOUT1');
  const exported = JSON.parse(text) as { export: { source_integrity: string; verified: boolean; redaction: { masked_values: number } }; events: TraceEvent[] };
  expect(JSON.parse(exported.events[1].payload_json).usage).toEqual({ input_tokens: 1296, output_tokens: 546, total_tokens: 1842 });
  expect(exported.export.source_integrity).toBe('invalid');
  expect(exported.export.verified).toBe(false);
  expect(exported.export.redaction.masked_values).toBe(2);
  const toast = document.querySelector('.action-feedback');
  expect(toast).toHaveTextContent(/2 values masked/);
  expect(toast).toHaveTextContent(/not verified/);
});
