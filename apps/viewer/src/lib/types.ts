export interface JournalFile {
  path: string;
  sha256: string;
  event_count: number;
}

/**
 * `abandoned`: no finalized journal and the recorder is gone; `premier recover` finalizes it.
 * `locked`: encrypted, and the server has no usable key; the evidence is sealed, not damaged.
 */
export type IntegrityStatus = 'live' | 'abandoned' | 'verified' | 'invalid' | 'locked' | 'unsupported';
/** What a verified trace is protected by. Only `signed` resists a deliberate rewrite. */
export type IntegrityProtection = 'digest_only' | 'sealed' | 'signed';

/** Format v2 tamper evidence recorded in the manifest at finalization. */
export interface ManifestSeal {
  chain_head: string;
  event_count: number;
  recovered?: boolean;
  digest: string;
  signature?: { algorithm: string; public_key: string; signature: string };
}

export interface ProcessTermination {
  kind: 'exit' | 'signal' | 'interrupted';
  exit_code?: number | null;
  signal?: number | null;
  signal_name?: string | null;
  core_dumped?: boolean;
}

export interface TraceDiagnostic {
  severity: 'warning';
  code: string;
  message: string;
  event_id?: string;
  sequence?: number;
}

export interface TraceManifest {
  format_version: number;
  trace_id: string;
  name?: string | null;
  command: string[];
  started_at: string;
  ended_at: string | null;
  exit_code: number | null;
  journal: JournalFile | null;
  capabilities?: string[];
  summary?: TraceListSummary;
  /** Directory basename; unique across copied artifacts that share a trace_id. */
  artifact?: string;
  integrity?: IntegrityStatus;
  integrity_detail?: string | null;
  integrity_protection?: IntegrityProtection;
  /** Fingerprint of the signing key stored in the trace; identifies the signer without vouching for it. */
  integrity_signer?: string;
  seal?: ManifestSeal;
  /** Structured recorder termination metadata (available on newer artifacts). */
  termination?: ProcessTermination;
  /** Advisory semantic validation findings; unknown/custom event kinds remain valid. */
  diagnostics?: TraceDiagnostic[];
  /** What the recorder was told to redact. Values it replaced read `[REDACTED]`. */
  redaction?: RedactionProvenance | null;
  /** Public encryption envelope; present when the trace is stored encrypted. */
  encryption?: unknown;
}

export interface RedactionProvenance {
  structured_defaults: boolean;
  custom_fields?: string[];
  terminal_literal_count?: number;
  terminal_regex_count?: number;
  terminal_multiline_regex_count?: number;
  [key: string]: unknown;
}

/**
 * An entry the server lists but cannot serve events for: encrypted without a usable key, written in
 * a later format, or damaged beyond reading its manifest. Its `integrity_detail` says which.
 */
export function isUnreadable(trace: Pick<TraceManifest, 'integrity' | 'journal' | 'format_version' | 'trace_id'>): boolean {
  if (trace.integrity === 'locked' || trace.integrity === 'unsupported') return true;
  return trace.integrity === 'invalid' && trace.journal === null
    && (trace.format_version === 0 || trace.trace_id.startsWith('damaged:'));
}

export interface TraceListSummary {
  display_name: string | null;
  actor_count: number;
  issue_count: number;
  event_count: number;
}

export interface TraceEvent {
  event_id: string;
  trace_id: string;
  sequence: number;
  timestamp: string;
  kind: string;
  source: string;
  payload_json: string;
  actor_id: string;
  actor_type: string;
  parent_event_id: string;
  span_id: string;
  parent_span_id: string;
  correlation_id: string;
  status: string;
  duration_ms: number;
  links: string[];
  /** Hash of the previous event's canonical bytes (format v2). */
  prev_hash?: string;
}

/**
 * Decode payload_json into a plain object safe for Object.entries / inspector rows.
 * JSON null, arrays, and scalars are wrapped so the workspace never white-screens.
 */
export function eventPayload(event: TraceEvent): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(event.payload_json);
    if (parsed === null) return { value: null };
    if (Array.isArray(parsed)) return { items: parsed };
    if (typeof parsed === 'object') return parsed as Record<string, unknown>;
    return { value: parsed };
  } catch {
    return { raw: event.payload_json };
  }
}

/** Stable list key that survives copied .atrace directories with colliding trace_ids. */
export function listKey(trace: Pick<TraceManifest, 'trace_id' | 'artifact'>): string {
  return trace.artifact || trace.trace_id;
}

/** The recorder stopped without finalizing this trace. */
export function isAbandoned(trace: Pick<TraceManifest, 'integrity'>): boolean {
  return trace.integrity === 'abandoned';
}

/** Still being written by a running recorder, so there is something to tail. */
export function isRecording(
  trace: Pick<TraceManifest, 'ended_at' | 'integrity'> & Partial<Pick<TraceManifest, 'journal' | 'format_version' | 'trace_id'>>
): boolean {
  // A locked, unsupported or damaged entry has no end time either, and nothing to tail.
  const damaged = trace.integrity === 'invalid' && trace.journal === null
    && (trace.format_version === 0 || Boolean(trace.trace_id?.startsWith('damaged:')));
  return !trace.ended_at && !isAbandoned(trace)
    && trace.integrity !== 'locked' && trace.integrity !== 'unsupported' && !damaged;
}

/** The family a kind is filed under; `other` is every kind the viewer has no tab for. */
export type EventFamily = 'agent' | 'model' | 'tool' | 'approval' | 'process' | 'other';
export type EventCategory = 'all' | EventFamily | 'error';

export interface EventFilters {
  search: string;
  category: EventCategory;
  actorId: string | null;
  errorsOnly: boolean;
  /** When set, only events sharing this correlation_id remain in scope. */
  correlationId: string | null;
}

export interface AssistantAvailability {
  provider: string;
  label: string;
  installed: boolean;
  available: boolean;
  reason?: string;
}

export type AssistantMessageRole = 'user' | 'assistant';

export interface AssistantHistoryMessage {
  role: AssistantMessageRole;
  content: string;
}

export interface AssistantRequest {
  provider: string;
  prompt: string;
  selected_event_id?: string;
  history?: AssistantHistoryMessage[];
}

/** Which part of a trace an assistant prompt carries; see `AssistantContext` in premier-cli. */
export interface AssistantContext {
  scope: 'run' | 'event';
  total_events: number;
  /** Events sent in full: always the newest ones. */
  included_events: number;
  first_sequence?: number;
  last_sequence?: number;
  selected_sequence?: number;
  history_messages: number;
  prompt_chars: number;
}

export interface AssistantResponse {
  provider: string;
  answer: string;
  elapsed_ms: number;
  /** What the answer was based on. Absent from servers that predate it. */
  context?: AssistantContext;
}

/** The exact prompt a question would send, and what it covers. Nothing is sent to produce it. */
export interface AssistantPreview {
  context: AssistantContext;
  prompt: string;
}
