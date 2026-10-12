import { describe, expect, it } from 'vitest';
import { eventSummary } from './analysis';
import { buildInvestigationSummary } from './investigation';
import { modelCallUsage, modelUsage } from './modelUsage';
import { nativeText, payloadError, payloadModel, payloadTool, payloadTotalTokens, payloadUsage } from './nativePayload';
import { semanticEventKey } from './semanticCompare';
import type { TraceEvent, TraceManifest } from './types';

let sequence = 0;

/** Mirrors crates/premier-cli/src/adapters.rs normalize(): the provider object lives under payload.native. */
function adapterEvent(provider: string, kind: string, native: Record<string, unknown>, extra: Record<string, unknown> = {}, status = 'ok'): TraceEvent {
  sequence += 1;
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence, timestamp: '2026-07-13T12:00:00Z', kind,
    source: `adapter.${provider}.v1`,
    payload_json: JSON.stringify({ provider, adapter_schema_version: 1, native_type: String(native.type ?? 'unknown'), native, ...extra }),
    actor_id: provider, actor_type: 'agent', parent_event_id: '', span_id: '', parent_span_id: '', correlation_id: '',
    status, duration_ms: 0, links: []
  };
}

const claudeAssistant = {
  type: 'assistant',
  message: {
    id: 'msg-1', model: 'claude-sonnet-4-5', role: 'assistant',
    content: [{ type: 'text', text: 'I will read the config.' }],
    usage: { input_tokens: 120, output_tokens: 30, cache_read_input_tokens: 900, cache_creation_input_tokens: 40 }
  }
};
const claudeToolUse = {
  type: 'assistant',
  message: {
    id: 'msg-2', model: 'claude-sonnet-4-5', role: 'assistant',
    content: [{ type: 'tool_use', id: 'tool-1', name: 'Read', input: { file_path: '/repo/config.toml' } }],
    usage: { input_tokens: 200, output_tokens: 12 }
  }
};
const claudeToolError = {
  type: 'user',
  message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tool-1', is_error: true, content: 'ENOENT: no such file' }] }
};
const claudeResult = {
  type: 'result', subtype: 'success', is_error: false, num_turns: 2, result: 'Config reviewed.', total_cost_usd: 0.0123,
  usage: { input_tokens: 320, output_tokens: 42 }, modelUsage: { 'claude-sonnet-4-5': { inputTokens: 320, outputTokens: 42 } }
};

describe('native adapter payloads', () => {
  it('reads model, tokens, cache, and response text from a native Claude message', () => {
    const call = modelCallUsage(adapterEvent('claude', 'model.response', claudeAssistant));
    expect(call).not.toBeNull();
    expect(call?.model).toBe('claude-sonnet-4-5');
    expect(call?.provider).toBe('claude');
    expect(call?.tokens).toMatchObject({ input: 120, output: 30, cacheRead: 900, cacheWrite: 40, total: 150 });
    expect(call?.response).toBe('I will read the config.');
  });

  it('prefers normalized top-level fields over the native object', () => {
    const event = adapterEvent('claude', 'model.response', claudeAssistant, {
      model: 'claude-normalized', usage: { input_tokens: 1, output_tokens: 2, total_tokens: 3 }
    });
    const call = modelCallUsage(event);
    expect(call?.model).toBe('claude-normalized');
    expect(call?.tokens).toMatchObject({ input: 1, output: 2, total: 3, cacheRead: 900 });
    expect(eventSummary(event)).toBe('claude-normalized · I will read the config. · 3 tokens');
    const tool = adapterEvent('claude', 'tool.invocation', claudeToolUse, { tool: 'ReadFile' });
    expect(eventSummary(tool)).toBe('ReadFile');
    expect(eventSummary(adapterEvent('gemini', 'tool.result', { type: 'tool_result', name: 'read_file' }, { name: 'normalized_name' }))).toBe('normalized_name');
  });

  it('reports usage that was never recorded as unknown, not zero', () => {
    const call = modelCallUsage(adapterEvent('grok', 'model.response', { type: 'assistant.message', id: 'msg-1', content: 'done' }));
    expect(call?.model).toBe('Unknown model');
    expect(call?.tokens).toEqual({ input: null, output: null, cacheRead: null, cacheWrite: null, reasoning: null, total: null });
    expect(call?.costUsd).toBeNull();
    expect(call?.response).toBe('done');
    const { rollups } = modelUsage([call!.event]);
    expect(rollups[0]).toMatchObject({ hasInput: false, hasOutput: false, hasTotal: false, hasCost: false });
    expect(payloadTotalTokens({ provider: 'grok', native: { type: 'assistant.message' } })).toBeNull();
    expect(eventSummary(call!.event)).toBe('done');
  });

  it('reads the other provider usage shapes', () => {
    const grok = modelCallUsage(adapterEvent('grok', 'model.response', { type: 'assistant.message', model: 'grok-x', usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 }, content: 'ok' }));
    expect(grok).toMatchObject({ model: 'grok-x', tokens: { input: 10, output: 5, total: 15 } });
    const codex = modelCallUsage(adapterEvent('codex', 'model.response', { type: 'turn.completed', usage: { input_tokens: 800, cached_input_tokens: 600, output_tokens: 90 } }));
    expect(codex?.tokens).toMatchObject({ input: 800, output: 90, cacheRead: 600, total: 890 });
    const opencode = modelCallUsage(adapterEvent('opencode', 'model.response', { type: 'step_finish', part: { type: 'step-finish', cost: 0.002, tokens: { input: 50, output: 7, reasoning: 3, cache: { read: 11, write: 2 } } } }));
    expect(opencode?.tokens).toMatchObject({ input: 50, output: 7, reasoning: 3, cacheRead: 11, cacheWrite: 2, total: 57 });
    expect(opencode?.costUsd).toBe(0.002);
    const droid = modelCallUsage(adapterEvent('droid', 'model.response', { type: 'result', subtype: 'success', is_error: false, result: 'done', num_turns: 1 }));
    expect(droid?.response).toBe('done');
    expect(droid?.tokens.total).toBeNull();
  });

  it('counts per-message usage on tool events but never adds a cumulative run summary on top', () => {
    const events = [
      adapterEvent('claude', 'model.response', claudeAssistant),
      adapterEvent('claude', 'tool.invocation', claudeToolUse),
      adapterEvent('claude', 'provider.event', claudeResult)
    ];
    const { calls, rollups } = modelUsage(events);
    expect(calls.map((call) => call.event.kind)).toEqual(['model.response', 'tool.invocation']);
    expect(rollups).toHaveLength(1);
    expect(rollups[0]).toMatchObject({ model: 'claude-sonnet-4-5', calls: 2, input: 320, output: 42, total: 362 });
    expect(modelCallUsage(events[2])).toBeNull();
    expect(modelCallUsage(adapterEvent('claude', 'provider.event', claudeResult, { model: 'claude-sonnet-4-5', usage: { input_tokens: 320, output_tokens: 42, total_tokens: 362 } }))).toBeNull();
  });

  it('falls back to the run summary when no per-call usage was recorded', () => {
    const events = [
      adapterEvent('gemini', 'model.response', { type: 'message', role: 'assistant', content: 'hello' }),
      adapterEvent('gemini', 'provider.event', { type: 'result', status: 'success', stats: { total_tokens: 500, input_tokens: 420, output_tokens: 80 } })
    ];
    const { calls, rollups } = modelUsage(events);
    expect(calls).toHaveLength(2);
    expect(rollups.reduce((sum, row) => sum + row.total, 0)).toBe(500);
    expect(rollups.some((row) => row.hasTotal)).toBe(true);
  });

  it('summarizes native tool, model, and lifecycle rows by what happened', () => {
    expect(eventSummary(adapterEvent('claude', 'tool.invocation', { type: 'hook_started', hook_name: 'PreToolUse', tool_use_id: 'tool-1', tool_name: 'Read' }, {}, 'running'))).toBe('Read');
    expect(eventSummary(adapterEvent('claude', 'tool.invocation', claudeToolUse))).toBe('Read');
    expect(eventSummary(adapterEvent('codex', 'tool.result', { type: 'item.completed', item: { id: 'cmd-1', type: 'command_execution', command: 'rg TODO', exit_code: 0 } }))).toBe('rg TODO · exit 0');
    expect(eventSummary(adapterEvent('gemini', 'tool.result', { type: 'tool_result', tool_use_id: 'tool-1', name: 'read_file', status: 'success' }))).toBe('read_file');
    expect(eventSummary(adapterEvent('opencode', 'tool.invocation', { type: 'tool_use', id: 'tool-1', name: 'read' }, {}, 'running'))).toBe('read');
    expect(eventSummary(adapterEvent('kimi', 'tool.invocation', { role: 'assistant', content: [{ type: 'text', text: 'checking' }], tool_calls: [{ id: 'call-1', type: 'function', function: { name: 'Read', arguments: '{}' } }] }))).toBe('Read');
    expect(eventSummary(adapterEvent('kimi', 'tool.result', { role: 'tool', tool_call_id: 'call-1', content: 'ok' }))).toBe('Tool result · ok');
    expect(eventSummary(adapterEvent('claude', 'model.response', claudeAssistant))).toBe('claude-sonnet-4-5 · I will read the config. · 150 tokens');
    expect(eventSummary(adapterEvent('claude', 'agent.turn', { type: 'system', subtype: 'init', session_id: 'claude-session' }, {}, 'running'))).toBe('system init');
    expect(eventSummary(adapterEvent('codex', 'agent.turn', { type: 'thread.started', thread_id: 'codex-thread' }, {}, 'running'))).toBe('thread.started');
    expect(eventSummary(adapterEvent('claude', 'provider.event', claudeResult))).toBe('Config reviewed.');
    for (const event of [
      adapterEvent('claude', 'tool.invocation', claudeToolUse),
      adapterEvent('codex', 'agent.turn', { type: 'thread.started', thread_id: 'codex-thread' }),
      adapterEvent('grok', 'provider.event', { type: 'heartbeat' })
    ]) {
      expect(eventSummary(event)).not.toMatch(/^adapter\./);
    }
  });

  it('surfaces native errors in rows and in the investigation cause', () => {
    const failedCommand = adapterEvent('codex', 'tool.result', { type: 'item.completed', item: { id: 'cmd-2', type: 'command_execution', command: 'cargo test', exit_code: 101, aggregated_output: 'test failed: parser' } }, {}, 'error');
    expect(eventSummary(failedCommand)).toBe('cargo test · error: exit 101: test failed: parser');
    expect(eventSummary(adapterEvent('claude', 'tool.result', claudeToolError, {}, 'ok'))).toBe('Tool result · error: ENOENT: no such file');
    expect(eventSummary(adapterEvent('grok', 'model.response', { type: 'error', error: { message: 'rate limited' } }, {}, 'error'))).toBe('error: rate limited');
    expect(payloadError({ native: { type: 'result', is_error: true, result: 'Budget exceeded' } })).toBe('Budget exceeded');
    expect(payloadError({ native: { type: 'result', is_error: false, result: 'fine' } })).toBeNull();

    const trace: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', name: 'Codex run', command: ['codex', 'exec', '--json'],
      started_at: '2026-07-13T12:00:00Z', ended_at: '2026-07-13T12:00:09Z', exit_code: 1, journal: null
    };
    const summary = buildInvestigationSummary(trace, [adapterEvent('codex', 'agent.turn', { type: 'thread.started', thread_id: 't' }, {}, 'running'), failedCommand]);
    expect(summary.cause.detail).toBe('cargo test · error: exit 101: test failed: parser');
    expect(summary.failureChain.map((item) => item.summary).join(' ')).not.toMatch(/adapter\.codex/);
  });

  it('exposes the shared readers and keys comparisons by native tool identity', () => {
    const payload = JSON.parse(adapterEvent('claude', 'tool.invocation', claudeToolUse).payload_json) as Record<string, unknown>;
    expect(payloadModel(payload)).toBe('claude-sonnet-4-5');
    expect(payloadTool(payload)).toBe('Read');
    expect(payloadUsage(payload)).toMatchObject({ input_tokens: 200, output_tokens: 12 });
    expect(payloadTotalTokens(payload)).toBe(212);
    expect(nativeText({ native: claudeAssistant })).toBe('I will read the config.');
    expect(payloadModel({ native: claudeResult })).toBe('claude-sonnet-4-5');
    expect(payloadModel({ text: 'plain' })).toBeNull();
    expect(payloadTool({ command: 'ls -la' })).toBe('ls -la');
    expect(semanticEventKey(adapterEvent('gemini', 'tool.result', { type: 'tool_result', name: 'read_file' }))).toContain('read_file');
  });
});
