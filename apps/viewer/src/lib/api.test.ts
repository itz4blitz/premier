import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';

afterEach(() => vi.unstubAllGlobals());

describe('assistant API', () => {
  it('posts the provider, history, and selected event to the encoded trace route', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      provider: 'claude', answer: 'Inspect event 8.', elapsed_ms: 42
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetch);

    await api.askAssistant('trace/id', {
      provider: 'claude',
      prompt: 'What failed?',
      selected_event_id: 'event-8',
      history: [{ role: 'user', content: 'Summarize it.' }]
    });

    expect(fetch).toHaveBeenCalledWith('/api/traces/trace%2Fid/assistant', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        provider: 'claude', prompt: 'What failed?', selected_event_id: 'event-8',
        history: [{ role: 'user', content: 'Summarize it.' }]
      })
    }));
  });

  it('asks the preview route for the prompt a question would send, without running it', async () => {
    const preview = {
      context: { scope: 'event', total_events: 12, included_events: 4, selected_sequence: 8, history_messages: 1, prompt_chars: 640 },
      prompt: 'You are inspecting one event of a recorded run.'
    };
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(preview), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    const body = {
      provider: 'claude',
      prompt: 'What failed?',
      selected_event_id: 'event-8',
      history: [{ role: 'user' as const, content: 'Summarize it.' }]
    };

    await expect(api.previewAssistant('copy of/run.atrace', body)).resolves.toEqual(preview);

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith('/api/traces/copy%20of%2Frun.atrace/assistant/preview', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  });

  it('reports a preview the server refuses as an ApiError carrying its status and reason', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: 'unknown assistant provider' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    )));

    await expect(api.previewAssistant('trace', { provider: 'nobody', prompt: 'Help' }))
      .rejects.toMatchObject({ name: 'ApiError', status: 400, message: 'unknown assistant provider' });
  });

  it('surfaces the backend error instead of replacing it with a generic status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: 'assistant did not respond within 45 seconds' }),
      { status: 504, headers: { 'Content-Type': 'application/json' } }
    )));

    await expect(api.askAssistant('trace', { provider: 'claude', prompt: 'Help' }))
      .rejects.toThrow('assistant did not respond within 45 seconds');
  });
});

describe('request helpers', () => {
  it('loads a single trace detail and events list', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ trace_id: 't1', integrity: 'verified' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ event_id: 'e1' }]), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    await expect(api.trace('t/1')).resolves.toMatchObject({ integrity: 'verified' });
    await expect(api.events('t/1')).resolves.toEqual([{ event_id: 'e1' }]);
    expect(fetch).toHaveBeenNthCalledWith(1, '/api/traces/t%2F1', expect.any(Object));
    expect(fetch).toHaveBeenNthCalledWith(2, '/api/traces/t%2F1/events', expect.any(Object));
  });

  it('requests one bounded page after a sequence cursor and forwards the abort signal', async () => {
    const fetch = vi.fn().mockImplementation(async () => new Response(JSON.stringify([{ event_id: 'e6' }]), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    const abort = new AbortController();
    await expect(api.eventsPage('t/1', { afterSequence: 5, limit: 2, signal: abort.signal })).resolves.toEqual([{ event_id: 'e6' }]);
    expect(fetch).toHaveBeenCalledWith(
      '/api/traces/t%2F1/events?after_sequence=5&limit=2',
      expect.objectContaining({ signal: abort.signal })
    );
    await api.eventsPage('t1', { limit: 500 });
    expect(fetch).toHaveBeenLastCalledWith('/api/traces/t1/events?after_sequence=0&limit=500', expect.any(Object));
  });

  it('maps 401 responses to an authentication message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 401 })));
    await expect(api.traces()).rejects.toThrow('Authentication is required.');
  });

  it('falls back to status text when the error body is not JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status: 500 })));
    await expect(api.assistants()).rejects.toThrow('Request failed (500).');
  });

  it('ignores non-string error fields in JSON error bodies', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: { nested: true } }),
      { status: 502, headers: { 'Content-Type': 'application/json' } }
    )));
    await expect(api.traces()).rejects.toThrow('Request failed (502).');
  });
});

describe('stream API', () => {
  class FakeEventSource {
    static instances: FakeEventSource[] = [];
    onopen: ((event: Event) => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    private listeners = new Map<string, Array<(event: MessageEvent) => void>>();
    closed = false;
    url: string;

    constructor(url: string) {
      this.url = url;
      FakeEventSource.instances.push(this);
    }

    addEventListener(type: string, listener: (event: MessageEvent) => void) {
      const list = this.listeners.get(type) ?? [];
      list.push(listener);
      this.listeners.set(type, list);
    }

    dispatch(type: string, data: unknown) {
      for (const listener of this.listeners.get(type) ?? []) {
        listener({ data: JSON.stringify(data) } as MessageEvent);
      }
    }

    close() {
      this.closed = true;
    }
  }

  afterEach(() => {
    FakeEventSource.instances = [];
  });

  it('emits live events and records on trace.complete without reconnect thrash', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const events: unknown[] = [];
    const states: string[] = [];
    const completes: unknown[] = [];

    const close = api.stream(
      'trace-1',
      (event) => events.push(event),
      (state) => states.push(state),
      (manifest) => completes.push(manifest)
    );

    const source = FakeEventSource.instances[0];
    source.onopen?.(new Event('open'));
    source.dispatch('trace.event', { event_id: 'e1', sequence: 1 });
    source.dispatch('trace.complete', {
      trace_id: 'trace-1',
      ended_at: '2026-01-01T00:00:02Z',
      integrity: 'verified'
    });
    source.onerror?.(new Event('error'));

    expect(events).toHaveLength(1);
    expect(completes[0]).toMatchObject({ integrity: 'verified' });
    expect(states).toEqual(['live', 'recorded']);
    expect(source.closed).toBe(true);
    close();
  });

  it('follows the stream from a sequence cursor when the caller already holds earlier events', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    api.stream('trace/1', () => undefined, () => undefined, undefined, 4200);
    api.stream('trace/1', () => undefined, () => undefined);
    expect(FakeEventSource.instances[0].url).toBe('/api/traces/trace%2F1/stream?after_sequence=4200');
    expect(FakeEventSource.instances[1].url).toBe('/api/traces/trace%2F1/stream');
  });

  it('reports reconnecting while the stream is still open', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    api.stream('trace-1', () => undefined, (state) => states.push(state));
    const source = FakeEventSource.instances[0];
    source.onopen?.(new Event('open'));
    source.onerror?.(new Event('error'));
    expect(states).toEqual(['live', 'reconnecting']);
  });

  it('manual close after complete stays recorded', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    const close = api.stream('trace-1', () => undefined, (state) => states.push(state));
    const source = FakeEventSource.instances[0];
    source.dispatch('trace.complete', { trace_id: 'trace-1', integrity: 'verified' });
    close();
    expect(states).toEqual(['recorded']);
    expect(source.closed).toBe(true);
  });

  it('ignores events after the stream has been closed', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const events: unknown[] = [];
    const states: string[] = [];
    const close = api.stream('trace-1', (event) => events.push(event), (state) => states.push(state));
    const source = FakeEventSource.instances[0];
    close();
    close(); // second close is a no-op
    source.onopen?.(new Event('open'));
    source.dispatch('trace.event', { event_id: 'late' });
    source.dispatch('trace.complete', { trace_id: 'trace-1' });
    source.onerror?.(new Event('error'));
    expect(events).toEqual([]);
    expect(states).toEqual(['disconnected']);
  });

  it('stops instead of reconnecting when the server reports the trace unreadable', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    const completes: unknown[] = [];
    api.stream('trace-1', () => undefined, (state) => states.push(state), (manifest) => completes.push(manifest));
    const source = FakeEventSource.instances[0];
    source.onopen?.(new Event('open'));
    source.dispatch('trace.error', { error: 'the trace can no longer be read; see the premier server log' });
    // The server closes the connection next; EventSource must not be left to retry it.
    source.onerror?.(new Event('error'));
    expect(states).toEqual(['live', 'disconnected']);
    expect(completes).toEqual([]);
    expect(source.closed).toBe(true);
  });

  it('treats trace.abandoned as the end of the stream', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    const completes: unknown[] = [];
    const close = api.stream('trace-1', () => undefined, (state) => states.push(state), (manifest) => completes.push(manifest));
    const source = FakeEventSource.instances[0];
    source.onopen?.(new Event('open'));
    source.dispatch('trace.abandoned', { trace_id: 'trace-1', ended_at: null, integrity: 'abandoned', integrity_detail: 'Run premier recover.' });
    // The server closes the connection next; that must not read as a dropped stream.
    source.onerror?.(new Event('error'));
    close();
    expect(completes).toEqual([expect.objectContaining({ integrity: 'abandoned', integrity_detail: 'Run premier recover.' })]);
    expect(states).toEqual(['live', 'abandoned']);
    expect(source.closed).toBe(true);
  });

  it('ends as abandoned even when the abandoned frame carries no readable manifest', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    const completes: unknown[] = [];
    api.stream('trace-1', () => undefined, (state) => states.push(state), (manifest) => completes.push(manifest));
    const source = FakeEventSource.instances[0];
    const raw = source as unknown as { listeners: Map<string, Array<(event: MessageEvent) => void>> };
    source.onopen?.(new Event('open'));
    expect(() => raw.listeners.get('trace.abandoned')?.forEach((listener) => listener({ data: '{"trace_id": ' } as MessageEvent)))
      .not.toThrow();
    // The connection drops next; a finished stream must not be reported as reconnecting.
    source.onerror?.(new Event('error'));
    expect(completes).toEqual([]);
    expect(states).toEqual(['live', 'abandoned']);
    expect(source.closed).toBe(true);
  });

  it('closes on trace.abandoned for a caller that passed no completion handler', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    api.stream('trace-1', () => undefined, (state) => states.push(state));
    const source = FakeEventSource.instances[0];
    expect(() => source.dispatch('trace.abandoned', { trace_id: 'trace-1', integrity: 'abandoned' })).not.toThrow();
    expect(states).toEqual(['abandoned']);
    expect(source.closed).toBe(true);
  });

  it('ignores terminal frames that arrive after the caller closed the stream', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    const completes: unknown[] = [];
    const close = api.stream('trace-1', () => undefined, (state) => states.push(state), (manifest) => completes.push(manifest));
    const source = FakeEventSource.instances[0];
    source.onopen?.(new Event('open'));
    close();
    source.dispatch('trace.abandoned', { trace_id: 'trace-1', integrity: 'abandoned' });
    source.dispatch('trace.error', { error: 'the trace can no longer be read' });
    // Neither late frame may hand over a manifest or rewrite the state the caller already saw.
    expect(completes).toEqual([]);
    expect(states).toEqual(['live', 'disconnected']);
  });

  it('reports disconnected when the browser has given up on the stream', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    api.stream('trace-1', () => undefined, (state) => states.push(state));
    const source = FakeEventSource.instances[0] as unknown as { readyState: number; onerror: ((event: Event) => void) | null; closed: boolean };
    // What a 404, 401 or 502 answer leaves behind: EventSource.CLOSED, with no retry scheduled.
    source.readyState = 2;
    source.onerror?.(new Event('error'));
    source.onerror?.(new Event('error'));
    expect(states).toEqual(['disconnected']);
    expect(source.closed).toBe(true);
  });

  it('drops a frame that is not JSON instead of throwing inside the listener', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const events: unknown[] = [];
    const states: string[] = [];
    api.stream('trace-1', (event) => events.push(event), (state) => states.push(state));
    const source = FakeEventSource.instances[0] as unknown as { listeners: Map<string, Array<(event: MessageEvent) => void>> };
    const send = (type: string, data: string) => source.listeners.get(type)?.forEach((listener) => listener({ data } as MessageEvent));
    expect(() => send('trace.event', '{"event_id": tru')).not.toThrow();
    send('trace.event', '{"event_id":"ok"}');
    expect(events).toEqual([{ event_id: 'ok' }]);
    expect(() => send('trace.complete', 'not json')).not.toThrow();
    expect(states).toEqual(['recorded']);
  });

  it('carries the HTTP status on a failed request', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }));
    await expect(api.traces()).rejects.toMatchObject({ name: 'ApiError', status: 401, message: 'Authentication is required.' });
  });
});
