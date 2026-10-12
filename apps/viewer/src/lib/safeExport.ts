import type { TraceEvent, TraceManifest } from './types';

export const STRUCTURED_MARKER = '[REDACTED BY PREMIER]';
export const TEXT_MARKER = '[REDACTED]';

/** Mutable tally so callers can report how much was actually masked. */
export interface RedactionStats {
  masked: number;
}

const containsSensitive = ['password', 'passwd', 'secret', 'authorization', 'cookie', 'apikey', 'privatekey', 'accesskey', 'credential'];

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** `access_token`, `idToken`, `token` are credentials; `input_tokens`, `token_count`, `tokenizer` are not. */
function isTokenKey(normalized: string): boolean {
  return normalized.endsWith('token');
}

/**
 * Credential-bearing field names, compared after dropping case and punctuation so `apiKey`, `api_key`,
 * and `X-API-Key` are one name. Mirrors the recorder's rule: usage counters such as `input_tokens`
 * are evidence, not secrets.
 */
export function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return normalized === 'auth'
    || isTokenKey(normalized)
    || containsSensitive.some((name) => normalized.includes(name));
}

// Anchored on `://` (no scheme prefix) so long unbroken text cannot trigger quadratic backtracking.
const urlPassword = /(:\/\/[^\s:/@]+:)[^\s@/]+@/g;
const keyValue = /(api[_-]?key|access[_-]?key(?:[_-]?id)?|private[_-]?key|secret|password|passwd|token|authorization|credentials?)((?:\\?["'])?\s*[=:]\s*)((?:bearer|basic)\s+)?(\\"[^"\\]*\\"|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;&"'}\]\\]+)/gi;
const cookieHeader = /((?:set-)?cookie\s*:\s*)[^\r\n"\\]+/gi;
const bearer = /(bearer\s+)[a-z0-9._~+/=-]+/gi;
const knownSecretShapes = /\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g;

function maskedLiteral(value: string): string {
  if (value.startsWith('\\"')) return `\\"${TEXT_MARKER}\\"`;
  if (value.startsWith('"')) return `"${TEXT_MARKER}"`;
  if (value.startsWith("'")) return `'${TEXT_MARKER}'`;
  return TEXT_MARKER;
}

/** Best-effort masking of credentials written into free text: log lines, headers, URLs, JSON fragments. */
export function redactString(value: string, stats: RedactionStats = { masked: 0 }): string {
  const count = () => { stats.masked += 1; };
  return value
    .replace(urlPassword, (_match, prefix: string) => { count(); return `${prefix}${TEXT_MARKER}@`; })
    .replace(keyValue, (match, key: string, separator: string, scheme: string | undefined, secret: string) => {
      const bare = secret.replace(/^\\?["']|\\?["']$/g, '');
      if (bare.startsWith('[REDACTED') || bare === '') return match;
      // A number after a token-named key is a count, never a credential.
      if (key.toLowerCase() === 'token' && !scheme && /^\d+(?:\.\d+)?$/.test(bare)) return match;
      count();
      return `${key}${separator}${scheme ?? ''}${maskedLiteral(secret)}`;
    })
    .replace(cookieHeader, (match, prefix: string) => {
      if (match.slice(prefix.length).startsWith('[REDACTED')) return match;
      count();
      return `${prefix}${TEXT_MARKER}`;
    })
    .replace(bearer, (_match, prefix: string) => { count(); return `${prefix}${TEXT_MARKER}`; })
    .replace(knownSecretShapes, () => { count(); return TEXT_MARKER; });
}

function alreadyRedacted(value: unknown): boolean {
  return typeof value === 'string' && value.startsWith('[REDACTED');
}

function redactStringValue(value: string, stats: RedactionStats): string {
  const trimmed = value.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const decoded = JSON.parse(value) as unknown;
      if (decoded && typeof decoded === 'object') {
        const nested: RedactionStats = { masked: 0 };
        const cleaned = safeExportValue(decoded, nested);
        // Untouched evidence keeps its original bytes; only re-encode when something was masked.
        if (nested.masked === 0) return value;
        stats.masked += nested.masked;
        return JSON.stringify(cleaned);
      }
    } catch {
      // Not a single JSON document (JSONL, truncated output, prose): fall through to pattern masking.
    }
  }
  return redactString(value, stats);
}

/**
 * Deep copy of `value` with credential fields and credential-looking text masked. Strings that hold a
 * JSON document (payload_json, captured stdout) are decoded and masked field by field.
 */
export function safeExportValue(value: unknown, stats: RedactionStats = { masked: 0 }): unknown {
  if (Array.isArray(value)) return value.map((item) => safeExportValue(item, stats));
  if (typeof value === 'string') return redactStringValue(value, stats);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => {
    if (!isSensitiveKey(key) || child === null || child === undefined || alreadyRedacted(child)) {
      return [key, safeExportValue(child, stats)];
    }
    // Counters and flags under a token-named key (`next_token: 3`) are not credentials.
    if (isTokenKey(normalizeKey(key)) && (typeof child === 'number' || typeof child === 'boolean')) return [key, child];
    stats.masked += 1;
    return [key, STRUCTURED_MARKER];
  }));
}

export interface SafeExportDocument {
  export: {
    format: 'premier.viewer-export.v1';
    exported_at: string;
    /** Integrity status the server reported for the source trace, or `unknown`. */
    source_integrity: string;
    /** Always false: a masked copy no longer matches the recorded digests. */
    verified: false;
    redaction: {
      best_effort: true;
      masked_values: number;
      structured_marker: string;
      text_marker: string;
    };
    note: string;
  };
  manifest: TraceManifest;
  events: TraceEvent[];
}

export interface SafeExport {
  document: SafeExportDocument;
  /** Human-readable summary of what the export is and is not. */
  label: string;
}

export function buildSafeExport(manifest: TraceManifest, events: TraceEvent[], exportedAt = new Date().toISOString()): SafeExport {
  const stats: RedactionStats = { masked: 0 };
  const cleaned = safeExportValue({ manifest, events }, stats) as { manifest: TraceManifest; events: TraceEvent[] };
  const sourceIntegrity = manifest.integrity ?? 'unknown';
  const masking = stats.masked > 0
    ? `${stats.masked} value${stats.masked === 1 ? '' : 's'} masked (best effort)`
    : 'no known secret patterns found';
  const source = sourceIntegrity === 'verified'
    ? 'copy of a verified source trace'
    : `source trace is not verified (${sourceIntegrity})`;
  return {
    document: {
      export: {
        format: 'premier.viewer-export.v1',
        exported_at: exportedAt,
        source_integrity: sourceIntegrity,
        verified: false,
        redaction: {
          best_effort: true,
          masked_values: stats.masked,
          structured_marker: STRUCTURED_MARKER,
          text_marker: TEXT_MARKER
        },
        note: 'Masked copy produced in the browser. Masking is pattern-based and may miss secrets; review before sharing. '
          + 'This file cannot be checked against the recorded digests. Use `premier export` for portable evidence.'
      },
      manifest: cleaned.manifest,
      events: cleaned.events
    },
    label: `Export created: ${masking}; ${source}`
  };
}
