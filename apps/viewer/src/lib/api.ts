import type {
  AssistantAvailability,
  AssistantRequest,
  AssistantResponse,
  TraceEvent,
  TraceManifest
} from './types';

export type StreamState = 'connecting' | 'live' | 'reconnecting' | 'recorded' | 'abandoned' | 'disconnected';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: 'application/json', ...init?.headers }
  });
  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.json() as { error?: unknown };
      if (typeof body.error === 'string') detail = body.error;
    } catch {
      // Non-JSON proxy and server errors still receive a useful status fallback.
    }
    const message = response.status === 401
      ? 'Authentication is required.'
      : detail || `Request failed (${response.status}).`;
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

/**
 * `traceId` in every call below is what the server resolves: a trace's artifact name (its
 * directory, `listKey(trace)`), or a trace id when only one served trace has it. Copies of a
 * recording share a trace id, and the server answers 409 for an id that names several.
 */
export const api = {
  traces: () => request<TraceManifest[]>('/api/traces'),
  trace: (traceId: string) => request<TraceManifest>(`/api/traces/${encodeURIComponent(traceId)}`),
  assistants: () => request<AssistantAvailability[]>('/api/assistants'),
  askAssistant: (traceId: string, body: AssistantRequest) => request<AssistantResponse>(
    `/api/traces/${encodeURIComponent(traceId)}/assistant`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }
  ),
  events: (traceId: string) => request<TraceEvent[]>(`/api/traces/${encodeURIComponent(traceId)}/events`),
  /** One bounded page of events with a sequence greater than `afterSequence`. */
  eventsPage: (
    traceId: string,
    page: { afterSequence?: number; limit: number; signal?: AbortSignal }
  ) => request<TraceEvent[]>(
    `/api/traces/${encodeURIComponent(traceId)}/events?after_sequence=${page.afterSequence ?? 0}&limit=${page.limit}`,
    { signal: page.signal }
  ),
  stream: (
    traceId: string,
    onEvent: (event: TraceEvent) => void,
    onState: (state: StreamState) => void,
    onComplete?: (manifest: TraceManifest) => void,
    /** Follow only events after this sequence; the caller already holds the earlier ones. */
    afterSequence = 0
  ) => {
    const resume = afterSequence > 0 ? `?after_sequence=${afterSequence}` : '';
    const source = new EventSource(`/api/traces/${encodeURIComponent(traceId)}/stream${resume}`);
    let closed = false;
    let completed = false;

    const close = (state: StreamState = 'disconnected') => {
      if (closed) return;
      closed = true;
      source.close();
      onState(state);
    };

    source.onopen = () => {
      if (!closed) onState('live');
    };
    source.addEventListener('trace.event', (message) => {
      if (closed) return;
      onEvent(JSON.parse((message as MessageEvent).data) as TraceEvent);
    });
    source.addEventListener('trace.complete', (message) => {
      if (closed) return;
      completed = true;
      const manifest = JSON.parse((message as MessageEvent).data) as TraceManifest;
      onComplete?.(manifest);
      close('recorded');
    });
    // The server's other terminal event: the recorder is gone, so nothing more will arrive. Its
    // manifest carries `integrity: 'abandoned'`; closing here keeps EventSource from reconnecting.
    source.addEventListener('trace.abandoned', (message) => {
      if (closed) return;
      completed = true;
      const manifest = JSON.parse((message as MessageEvent).data) as TraceManifest;
      onComplete?.(manifest);
      close('abandoned');
    });
    // The server gave up on a trace it can no longer read (deleted, damaged, or its key gone):
    // closing keeps EventSource from reconnecting to the same failure forever.
    source.addEventListener('trace.error', () => {
      if (closed) return;
      completed = true;
      close('disconnected');
    });
    source.onerror = () => {
      if (closed || completed) return;
      // EventSource reconnects automatically; surface reconnecting until complete arrives.
      onState('reconnecting');
    };
    return () => close(completed ? 'recorded' : 'disconnected');
  }
};
