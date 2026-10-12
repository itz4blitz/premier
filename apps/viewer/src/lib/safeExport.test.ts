import { describe, expect, it } from 'vitest';
import { buildSafeExport, isSensitiveKey, redactString, safeExportValue } from './safeExport';
import type { TraceEvent, TraceManifest } from './types';

const manifest: TraceManifest = {
  format_version: 1, trace_id: 'trace-1', name: 'Export', command: ['agent'],
  started_at: '2026-01-01T00:00:00Z', ended_at: '2026-01-01T00:00:01Z', exit_code: 0,
  journal: { path: 'events/000001.events.pb.zst', sha256: 'abc', event_count: 1 },
  integrity: 'verified'
};

function event(payload: unknown): TraceEvent {
  return {
    event_id: 'event-1', trace_id: 'trace-1', sequence: 1, timestamp: '2026-01-01T00:00:00Z', kind: 'model.response',
    source: 'sdk', payload_json: JSON.stringify(payload), actor_id: 'agent', actor_type: 'agent', parent_event_id: '',
    span_id: '', parent_span_id: '', correlation_id: '', status: 'ok', duration_ms: 0, links: []
  };
}

describe('isSensitiveKey', () => {
  it('does not treat token counts as secrets', () => {
    for (const key of [
      'input_tokens', 'output_tokens', 'total_tokens', 'input_tokens_by_role', 'input_tokens_details',
      'output_tokens_details', 'cached_tokens', 'reasoning_tokens', 'max_tokens', 'maxTokens', 'prompt_tokens',
      'completion_tokens', 'cache_read_input_tokens', 'token_count', 'tokenizer', 'tokens', 'token_usage', 'author', 'authored_by'
    ]) {
      expect(isSensitiveKey(key), key).toBe(false);
    }
  });

  it('recognizes credential fields in snake, camel, kebab, and header spellings', () => {
    for (const key of [
      'apiKey', 'api_key', 'API-KEY', 'x-api-key', 'openai_api_key', 'OPENAI_API_KEY', 'authorization', 'Authorization',
      'Proxy-Authorization', 'token', 'access_token', 'accessToken', 'refresh_token', 'id_token', 'session_token',
      'github_token', 'password', 'db_password', 'passwd', 'secret', 'client_secret', 'clientSecret', 'privateKey',
      'private_key', 'cookie', 'Set-Cookie', 'aws_access_key_id', 'aws_secret_access_key', 'secretAccessKey',
      'credentials', 'auth'
    ]) {
      expect(isSensitiveKey(key), key).toBe(true);
    }
  });
});

describe('safeExportValue', () => {
  it('keeps token usage numbers and still masks credentials beside them', () => {
    const usage = {
      cost_usd: 0.0047, input_tokens: 1296, input_tokens_by_role: { system: 400, user: 896 },
      input_tokens_details: { cached_tokens: 12 }, output_tokens: 546, output_tokens_details: { reasoning_tokens: 3 },
      total_tokens: 1842
    };
    const exported = safeExportValue({ usage, apiKey: 'sk-live-ABCDEFGHIJKLMNOP', authorization: 'Bearer abc.def', max_tokens: 4096 }) as Record<string, unknown>;
    expect(exported.usage).toEqual(usage);
    expect(exported.max_tokens).toBe(4096);
    expect(exported.apiKey).toBe('[REDACTED BY PREMIER]');
    expect(exported.authorization).toBe('[REDACTED BY PREMIER]');
  });

  it('treats a numeric value under a token-named key as a count, not a credential', () => {
    expect(safeExportValue({ token: 12, next_token: 3 })).toEqual({ token: 12, next_token: 3 });
    expect(safeExportValue({ token: 'abc' })).toEqual({ token: '[REDACTED BY PREMIER]' });
  });

  it('masks credentials inside stringified JSON values, including payload_json and stdout', () => {
    const exported = safeExportValue(event({
      stdout: '{"apiKey":"sk-live-STDOUT1","usage":{"input_tokens":7}}\n',
      nested: JSON.stringify({ inner: JSON.stringify({ api_key: 'sk-nested-1', total_tokens: 9 }) })
    })) as TraceEvent;
    expect(exported.payload_json).not.toContain('sk-live-STDOUT1');
    expect(exported.payload_json).not.toContain('sk-nested-1');
    const payload = JSON.parse(exported.payload_json) as { stdout: string; nested: string };
    expect(JSON.parse(payload.stdout)).toEqual({ apiKey: '[REDACTED BY PREMIER]', usage: { input_tokens: 7 } });
    expect(JSON.parse((JSON.parse(payload.nested) as { inner: string }).inner)).toEqual({ api_key: '[REDACTED BY PREMIER]', total_tokens: 9 });
  });

  it('leaves existing recorder redaction markers alone', () => {
    expect(safeExportValue({ api_key: '[REDACTED]' })).toEqual({ api_key: '[REDACTED]' });
  });
});

describe('redactString', () => {
  it('masks credentials in JSON fragments, log lines, headers, and URLs', () => {
    const cases: Array<[string, string]> = [
      ['log {"apiKey":"sk-live-STDOUT1"} done', 'sk-live-STDOUT1'],
      ['{"apiKey": "sk-a"}\n{"api_key": "sk-b"}', 'sk-a'],
      ['{"apiKey": "sk-a"}\n{"api_key": "sk-b"}', 'sk-b'],
      ['OPENAI_API_KEY=sk-env-value-1', 'sk-env-value-1'],
      ['x-api-key: sk-header-value', 'sk-header-value'],
      ['Authorization: Bearer abc.def.ghi', 'abc.def.ghi'],
      ['authorization: Basic dXNlcjpwYXNz', 'dXNlcjpwYXNz'],
      ['password = "hunter2 with spaces"', 'hunter2'],
      ['postgres://admin:s3cretpw@db.internal:5432/app', 's3cretpw'],
      // Split so the repository secret scan does not flag these fixtures.
      [`pushed with ${'ghp' + '_abcdefghijklmnopqrstuvwxyz0123456789'}`, 'ghp' + '_abcdefghijklmnopqrstuvwxyz0123456789'],
      ['key sk-proj-abcdefghijklmnopqrstuvwx in output', 'sk-proj-abcdefghijklmnopqrstuvwx'],
      [`aws ${'AKIA' + 'IOSFODNN7EXAMPLE'} used`, 'AKIA' + 'IOSFODNN7EXAMPLE'],
      ['access_token=ya29.a0AfH6SMBx&expires_in=3600', 'ya29.a0AfH6SMBx']
    ];
    for (const [input, secret] of cases) {
      const output = redactString(input);
      expect(output, input).not.toContain(secret);
      expect(output, input).toContain('[REDACTED]');
    }
    expect(redactString('access_token=ya29.a0AfH6SMBx&expires_in=3600')).toContain('expires_in=3600');
  });

  it('keeps quoting intact and leaves token counts readable', () => {
    expect(redactString('"x-api-key: sk-header-value"')).toBe('"x-api-key: [REDACTED]"');
    expect(redactString('{"apiKey":"sk-a","model":"m"}')).toBe('{"apiKey":"[REDACTED]","model":"m"}');
    for (const text of ['input_tokens: 1296', 'total_tokens=1842', '"output_tokens": 546', 'tokens: 12', 'max_tokens=4096', 'token count: 9', 'used 1842 tokens']) {
      expect(redactString(text), text).toBe(text);
    }
  });
});

describe('redactString performance', () => {
  it('stays linear on large unbroken output', () => {
    const blob = `${'a'.repeat(1_000_000)} token=abc123 ${'0123456789abcdef'.repeat(60_000)}`;
    const started = performance.now();
    const output = redactString(blob);
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(output).toContain('token=[REDACTED]');
    expect(output.length).toBe(blob.length - 'abc123'.length + '[REDACTED]'.length);
  }, 30_000);
});

describe('buildSafeExport', () => {
  it('labels the artifact as a best-effort redacted copy and carries the source integrity status', () => {
    const { document: artifact, label } = buildSafeExport(manifest, [event({ usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 }, apiKey: 'sk-live-1' })], '2026-01-02T00:00:00Z');
    expect(artifact.export.format).toBe('premier.viewer-export.v1');
    expect(artifact.export.exported_at).toBe('2026-01-02T00:00:00Z');
    expect(artifact.export.source_integrity).toBe('verified');
    expect(artifact.export.verified).toBe(false);
    expect(artifact.export.redaction.best_effort).toBe(true);
    expect(artifact.export.redaction.masked_values).toBe(1);
    expect(label).toMatch(/1 value masked/);
    expect(label).not.toMatch(/\bverified\b(?! source)/i);
    expect(JSON.parse(artifact.events[0].payload_json)).toEqual({ usage: { input_tokens: 5, output_tokens: 2, total_tokens: 7 }, apiKey: '[REDACTED BY PREMIER]' });
  });

  it('never reports a verified source unless the manifest integrity status is verified', () => {
    for (const integrity of ['invalid', 'live', undefined] as const) {
      const { document: artifact, label } = buildSafeExport({ ...manifest, integrity }, [event({ ok: true })]);
      expect(artifact.export.source_integrity).toBe(integrity ?? 'unknown');
      expect(artifact.export.verified).toBe(false);
      expect(label).not.toMatch(/verified source/i);
      expect(label).toMatch(/not verified|unverified/i);
      expect(artifact.export.redaction.masked_values).toBe(0);
      expect(label).toMatch(/no known secret patterns found/i);
    }
    expect(buildSafeExport(manifest, []).label).toMatch(/verified source/i);
  });
});
