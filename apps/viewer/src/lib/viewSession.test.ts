import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearViewSession, readViewSession, writeViewSession } from './viewSession';
import type { TraceEvent, TraceManifest } from './types';

const trace: TraceManifest = {
  format_version: 1,
  trace_id: 'trace-a',
  command: ['agent'],
  started_at: '2026-01-01T00:00:00Z',
  ended_at: '2026-01-01T00:00:01Z',
  exit_code: 0,
  journal: { path: 'events/000001.events.pb.zst', sha256: 'abc', event_count: 1 }
};

const event: TraceEvent = {
  event_id: 'e1',
  trace_id: 'trace-a',
  sequence: 4,
  timestamp: '2026-01-01T00:00:00Z',
  kind: 'tool.execution',
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'agent',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: 's',
  parent_span_id: '',
  correlation_id: '',
  status: 'ok',
  duration_ms: 0,
  links: []
};

afterEach(() => {
  clearViewSession();
});

describe('viewSession', () => {
  it('round-trips a snapshot for the matching trace', () => {
    writeViewSession({
      traces: [trace],
      selectedTrace: trace,
      events: [event],
      selectedSequence: 4
    });
    const hit = readViewSession('trace-a');
    expect(hit?.selectedTrace.trace_id).toBe('trace-a');
    expect(hit?.events).toHaveLength(1);
    expect(hit?.selectedSequence).toBe(4);
  });

  it('misses when the requested trace id differs', () => {
    writeViewSession({
      traces: [trace],
      selectedTrace: trace,
      events: [event],
      selectedSequence: 4
    });
    expect(readViewSession('other')).toBeNull();
  });

  it('expires stale snapshots', () => {
    writeViewSession({
      traces: [trace],
      selectedTrace: trace,
      events: [event],
      selectedSequence: 4
    });
    const raw = sessionStorage.getItem('premier.viewer.session.v1');
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!);
    parsed.savedAt = Date.now() - 31 * 60 * 1000;
    sessionStorage.setItem('premier.viewer.session.v1', JSON.stringify(parsed));
    expect(readViewSession('trace-a')).toBeNull();
  });

  it('marks a snapshot that holds only the head of a long run', () => {
    const journal = Array.from({ length: 2_600 }, (_, index) => ({ ...event, event_id: `e${index}`, sequence: index + 1 }));
    writeViewSession({ traces: [trace], selectedTrace: trace, events: journal, selectedSequence: null });
    const hit = readViewSession('trace-a');
    expect(hit?.events).toHaveLength(2_500);
    expect(hit?.truncated).toBe(true);
    writeViewSession({ traces: [trace], selectedTrace: trace, events: [event], selectedSequence: null });
    expect(readViewSession('trace-a')?.truncated).toBe(false);
  });

  it('does not write the events of an encrypted trace to browser storage', () => {
    const encrypted = { ...trace, encryption: { algorithm: 'xchacha20-poly1305' } };
    writeViewSession({ traces: [encrypted], selectedTrace: encrypted, events: [{ ...event, payload_json: '{"secret":"plaintext"}' }], selectedSequence: 4 });
    expect(sessionStorage.getItem('premier.viewer.session.v1')).not.toContain('plaintext');
    expect(readViewSession('trace-a')).toMatchObject({ events: [], truncated: true });
  });

  it('drops the previous snapshot when a write fails', () => {
    writeViewSession({ traces: [trace], selectedTrace: trace, events: [event], selectedSequence: 4 });
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('full', 'QuotaExceededError'); });
    try {
      writeViewSession({ traces: [trace], selectedTrace: { ...trace, trace_id: 'trace-b' }, events: [event], selectedSequence: 4 });
    } finally {
      setItem.mockRestore();
    }
    // The older run must not come back on reload as if it were the one last opened.
    expect(readViewSession()).toBeNull();
  });
});
