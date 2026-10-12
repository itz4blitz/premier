import { listKey, type TraceEvent, type TraceManifest } from './types';

const sessionKey = 'premier.viewer.session.v1';
const maxAgeMs = 30 * 60 * 1000;
/** Cap cached events so large journals don't blow sessionStorage. */
const maxCachedEvents = 2_500;

/**
 * What a reload repaints from before the server answers: the run list, the open run's manifest and
 * the head of its journal, kept in this tab's sessionStorage for up to 30 minutes. It is a stand-in,
 * never the record: the viewer reloads the run from the server straight away. Described for users
 * in docs/cli.md ("The reload cache").
 */
export interface ViewSessionSnapshot {
  version: 1;
  savedAt: number;
  traces: TraceManifest[];
  selectedTrace: TraceManifest;
  events: TraceEvent[];
  selectedSequence: number | null;
  /** `events` is only the head of the run, so an event missing from it may still exist. */
  truncated?: boolean;
}

function canUseStorage(): boolean {
  return typeof sessionStorage !== 'undefined';
}

export function readViewSession(traceId?: string | null): ViewSessionSnapshot | null {
  if (!canUseStorage()) return null;
  try {
    const raw = sessionStorage.getItem(sessionKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ViewSessionSnapshot;
    if (!parsed || parsed.version !== 1 || !parsed.selectedTrace || !Array.isArray(parsed.events)) return null;
    if (!Number.isFinite(parsed.savedAt) || Date.now() - parsed.savedAt > maxAgeMs) return null;
    // `traceId` is the trace's artifact name, or its trace id in a link from an older build.
    if (traceId && listKey(parsed.selectedTrace) !== traceId && parsed.selectedTrace.trace_id !== traceId) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function writeViewSession(input: {
  traces: TraceManifest[];
  selectedTrace: TraceManifest;
  events: TraceEvent[];
  selectedSequence: number | null;
}): void {
  if (!canUseStorage()) return;
  // The events of an encrypted trace are plaintext only in memory. Browser storage would keep a
  // decrypted copy on disk, so for those only the manifests are cached.
  const cached = input.selectedTrace.encryption ? [] : input.events.slice(0, maxCachedEvents);
  try {
    const snapshot: ViewSessionSnapshot = {
      version: 1,
      savedAt: Date.now(),
      traces: input.traces.slice(0, 80),
      selectedTrace: input.selectedTrace,
      events: cached,
      selectedSequence: input.selectedSequence,
      truncated: cached.length < input.events.length
    };
    sessionStorage.setItem(sessionKey, JSON.stringify(snapshot));
  } catch {
    // Quota or private mode: the paint works without a cache. Drop what was stored before, or the
    // next reload would repaint an older run as if it were this one.
    clearViewSession();
  }
}

export function clearViewSession(): void {
  if (!canUseStorage()) return;
  try {
    sessionStorage.removeItem(sessionKey);
  } catch {
    // ignore
  }
}
