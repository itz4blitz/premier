import { describe, expect, it } from 'vitest';
import { eventPayload, isAbandoned, isRecording, isUnreadable, listKey, type TraceEvent, type TraceManifest } from './types';

const baseEvent = (payload_json: string): TraceEvent => ({
  event_id: 'e1',
  trace_id: 't1',
  sequence: 1,
  timestamp: '2026-01-01T00:00:00Z',
  kind: 'session.start',
  source: 'test',
  payload_json,
  actor_id: 'root',
  actor_type: 'process',
  parent_event_id: '',
  span_id: 's',
  parent_span_id: '',
  correlation_id: '',
  status: 'ok',
  duration_ms: 0,
  links: []
});

describe('eventPayload', () => {
  it('returns objects as records', () => {
    expect(eventPayload(baseEvent('{"tool":"rg"}'))).toEqual({ tool: 'rg' });
  });

  it('survives JSON null without throwing', () => {
    expect(eventPayload(baseEvent('null'))).toEqual({ value: null });
    expect(() => Object.entries(eventPayload(baseEvent('null')))).not.toThrow();
  });

  it('wraps arrays and scalars', () => {
    expect(eventPayload(baseEvent('[1,2]'))).toEqual({ items: [1, 2] });
    expect(eventPayload(baseEvent('"hello"'))).toEqual({ value: 'hello' });
    expect(eventPayload(baseEvent('42'))).toEqual({ value: 42 });
    expect(eventPayload(baseEvent('true'))).toEqual({ value: true });
  });

  it('returns raw text for invalid JSON', () => {
    expect(eventPayload(baseEvent('{broken'))).toEqual({ raw: '{broken' });
  });
});

describe('listKey', () => {
  const manifest = (overrides: Partial<TraceManifest> = {}): TraceManifest => ({
    format_version: 1,
    trace_id: 'shared-id',
    command: ['agent'],
    started_at: '2026-01-01T00:00:00Z',
    ended_at: '2026-01-01T00:00:01Z',
    exit_code: 0,
    journal: null,
    ...overrides
  });

  it('prefers artifact when present so copied traces stay unique', () => {
    expect(listKey(manifest({ artifact: 'original.atrace' }))).toBe('original.atrace');
    expect(listKey(manifest({ artifact: 'copy.atrace' }))).toBe('copy.atrace');
  });

  it('falls back to trace_id', () => {
    expect(listKey(manifest())).toBe('shared-id');
  });
});

describe('isUnreadable', () => {
  const entry = (overrides: Partial<TraceManifest> = {}): TraceManifest => ({
    format_version: 2, trace_id: 't1', command: ['agent'], started_at: '2026-01-01T00:00:00Z',
    ended_at: null, exit_code: null, journal: null,
    ...overrides
  });
  const journal = { path: 'events.jsonl', sha256: 'digest', event_count: 3 };

  it('treats sealed and later-format entries as unreadable whatever else they carry', () => {
    expect(isUnreadable(entry({ integrity: 'locked', journal }))).toBe(true);
    expect(isUnreadable(entry({ integrity: 'unsupported', journal }))).toBe(true);
  });

  it('treats an invalid entry with no journal as unreadable when its manifest could not be read', () => {
    expect(isUnreadable(entry({ integrity: 'invalid', format_version: 0 }))).toBe(true);
    expect(isUnreadable(entry({ integrity: 'invalid', trace_id: 'damaged:broken.atrace' }))).toBe(true);
  });

  it('keeps an invalid entry readable when its manifest and journal are there to inspect', () => {
    // Failed verification, but the manifest was read: the events can still be shown.
    expect(isUnreadable(entry({ integrity: 'invalid' }))).toBe(false);
    expect(isUnreadable(entry({ integrity: 'invalid', journal, format_version: 0 }))).toBe(false);
    expect(isUnreadable(entry({ integrity: 'invalid', journal, trace_id: 'damaged:broken.atrace' }))).toBe(false);
    // Only a leading `damaged:` marks the placeholder id.
    expect(isUnreadable(entry({ integrity: 'invalid', trace_id: 'run-damaged:1' }))).toBe(false);
  });

  it('leaves live, verified, abandoned and unreported entries readable', () => {
    expect(isUnreadable(entry({ integrity: 'live', format_version: 0 }))).toBe(false);
    expect(isUnreadable(entry({ integrity: 'verified', journal }))).toBe(false);
    expect(isUnreadable(entry({ integrity: 'abandoned', trace_id: 'damaged:x' }))).toBe(false);
    expect(isUnreadable(entry())).toBe(false);
  });
});

describe('recording state', () => {
  const open: TraceManifest = {
    format_version: 1, trace_id: 't1', command: ['agent'], started_at: '2026-01-01T00:00:00Z',
    ended_at: null, exit_code: null, journal: null
  };

  it('tails only traces whose recorder is still running', () => {
    expect(isRecording({ ...open, integrity: 'live' })).toBe(true);
    // Older servers do not report integrity for an open trace.
    expect(isRecording(open)).toBe(true);
    expect(isRecording({ ...open, integrity: 'abandoned' })).toBe(false);
    expect(isRecording({ ...open, ended_at: '2026-01-01T00:00:01Z', integrity: 'verified' })).toBe(false);
  });

  it('does not tail an entry that is sealed, from a later format, or damaged', () => {
    expect(isRecording({ ...open, integrity: 'locked' })).toBe(false);
    expect(isRecording({ ...open, integrity: 'unsupported' })).toBe(false);
    // A manifest the server could not read: no format version, or a placeholder id.
    expect(isRecording({ ...open, integrity: 'invalid', format_version: 0 })).toBe(false);
    expect(isRecording({ ...open, integrity: 'invalid', trace_id: 'damaged:broken.atrace' })).toBe(false);
  });

  it('keeps tailing an invalid entry that is not a damaged placeholder', () => {
    // Readable manifest, journal not written yet: the recorder may still be running.
    expect(isRecording({ ...open, integrity: 'invalid' })).toBe(true);
    // Callers that hold only part of a manifest: no trace id to inspect, or no journal field at all.
    expect(isRecording({ ended_at: null, integrity: 'invalid', journal: null, format_version: 2 })).toBe(true);
    expect(isRecording({ ended_at: null, integrity: 'invalid' })).toBe(true);
    // A damaged-looking id on an entry that does have a journal is not a damaged placeholder.
    const journal = { path: 'events.jsonl', sha256: 'digest', event_count: 3 };
    expect(isRecording({ ...open, integrity: 'invalid', journal, format_version: 0, trace_id: 'damaged:x' })).toBe(true);
  });

  it('recognizes abandoned traces', () => {
    expect(isAbandoned({ ...open, integrity: 'abandoned' })).toBe(true);
    expect(isAbandoned({ ...open, integrity: 'live' })).toBe(false);
    expect(isAbandoned(open)).toBe(false);
  });
});
