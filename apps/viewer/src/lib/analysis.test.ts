import { describe, expect, it } from 'vitest';
import { actorInventory, awaitingApprovals, categoryOf, countByCategory, eventSummary, familyOf, filterEvents, isIssue, isProcessNoise, materialEvent, runHealth, stripControlSequences, summarizeAgents, timelineLayout, traceTimeBounds } from './analysis';
import type { TraceEvent, TraceManifest } from './types';

function event(sequence: number, actor: string, kind: string, status = 'ok'): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence,
    timestamp: '2026-07-13T12:00:01Z', kind, source: 'sdk', payload_json: '{}',
    actor_id: actor, actor_type: actor === 'root' ? 'agent' : 'subagent', parent_event_id: '',
    span_id: `span-${sequence}`, parent_span_id: actor === 'root' ? '' : 'root-span',
    correlation_id: '', status, duration_ms: 0, links: []
  };
}

const events = [
  event(1, 'root', 'agent.delegation'),
  event(2, 'researcher', 'model.response'),
  event(3, 'coder', 'tool.execution'),
  event(4, 'reviewer', 'tool.error', 'error')
];

describe('agent trace analysis', () => {
  it('treats PTY output like piped output when collapsing noise and choosing the material event', () => {
    const terminal = event(1, 'root', 'process.terminal');
    const tool = event(2, 'coder', 'tool.execution');
    for (const kind of ['process.stdout', 'process.stderr', 'process.terminal']) {
      expect(isProcessNoise(event(1, 'root', kind)), kind).toBe(true);
    }
    expect(isProcessNoise(tool)).toBe(false);
    // Output that is itself an issue is never hidden as noise.
    expect(isProcessNoise(event(3, 'root', 'process.terminal', 'error'))).toBe(false);
    expect(materialEvent([terminal, event(3, 'root', 'process.exit')])?.kind).toBe('process.exit');
    expect(materialEvent([terminal, tool])).toBe(tool);
  });

  it('summarizes independent agent lanes and failures', () => {
    const agents = summarizeAgents(events);
    expect(agents.map((agent) => agent.id)).toEqual(['root', 'researcher', 'coder', 'reviewer']);
    expect(agents.at(-1)).toMatchObject({ errors: 1, status: 'error' });
  });

  it('combines actor, category, search, and error filters', () => {
    expect(filterEvents(events, { search: '', category: 'tool', actorId: 'coder', errorsOnly: false, correlationId: null })).toHaveLength(1);
    expect(filterEvents(events, { search: 'reviewer', category: 'all', actorId: null, errorsOnly: true, correlationId: null })[0].kind).toBe('tool.error');
  });

  it('filters by correlation id', () => {
    const correlated = [
      { ...event(1, 'coder', 'approval.request'), correlation_id: 'apr-1' },
      { ...event(2, 'brad', 'approval.decision'), correlation_id: 'apr-1' },
      { ...event(3, 'coder', 'tool.execution'), correlation_id: 'other' }
    ];
    expect(filterEvents(correlated, {
      search: '', category: 'all', actorId: null, errorsOnly: false, correlationId: 'apr-1'
    })).toHaveLength(2);
  });

  it('keeps failed tool events in both their recorded family and the issue facet', () => {
    const failedTool = event(5, 'coder', 'tool.execution_failed', 'blocked');
    expect(isIssue(failedTool)).toBe(true);
    expect(filterEvents([failedTool], { search: '', category: 'tool', actorId: null, errorsOnly: false, correlationId: null })).toEqual([failedTool]);
    expect(filterEvents([failedTool], { search: '', category: 'error', actorId: null, errorsOnly: false, correlationId: null })).toEqual([failedTool]);
  });

  it('separates runtime processes, coordinating agents, subagents, and humans', () => {
    const mixed = [
      { ...event(1, 'root', 'process.stdout'), actor_type: 'process' },
      { ...event(2, 'coordinator', 'agent.turn'), actor_type: 'agent' },
      { ...event(3, 'researcher', 'agent.spawn'), actor_type: 'subagent' },
      { ...event(4, 'brad', 'approval.decision'), actor_type: 'human' }
    ];
    expect(actorInventory(mixed)).toEqual({ processes: 1, agents: 1, subagents: 1, humans: 1, systems: 0 });
  });

  it('reports recorded errors even when the process exits cleanly', () => {
    const trace: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '', exit_code: 0, journal: null
    };
    expect(runHealth(trace, [event(1, 'reviewer', 'tool.error', 'error')])).toMatchObject({ label: 'Needs attention', tone: 'warning' });
    expect(runHealth({ ...trace, exit_code: 7 }, [])).toMatchObject({ label: 'Failed', detail: 'Exit 7' });
    expect(runHealth({ ...trace, exit_code: 143, termination: { kind: 'signal', signal: 15, signal_name: 'SIGTERM' } }, [])).toMatchObject({ label: 'Failed', detail: 'Terminated by SIGTERM' });
    expect(runHealth({ ...trace, exit_code: 130, termination: { kind: 'interrupted', exit_code: 130 } }, [])).toMatchObject({ label: 'Interrupted', detail: 'Recovered after recorder interruption' });
  });

  it('never presents integrity-invalid journals as passed', () => {
    const trace: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '2026-01-01',
      exit_code: 0, journal: null, integrity: 'invalid', integrity_detail: 'journal digest mismatch'
    };
    expect(runHealth(trace, [])).toMatchObject({
      label: 'Unverified',
      tone: 'error',
      detail: 'journal digest mismatch'
    });
    expect(runHealth({ ...trace, integrity_detail: null }, [])).toMatchObject({
      detail: 'Journal failed integrity verification'
    });
  });

  it('reports verified passed, live, blocked, and pending health states', () => {
    const base: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '2026-01-01',
      exit_code: 0, journal: null, integrity: 'verified'
    };
    expect(runHealth(base, [])).toMatchObject({ label: 'Passed', detail: expect.stringContaining('integrity verified') });
    expect(runHealth({ ...base, integrity_protection: 'sealed' }, []).detail).toContain('unsigned, self-consistent only');
    expect(runHealth({ ...base, integrity_protection: 'digest_only' }, []).detail).toContain('unsigned, v1 digest only');
    expect(runHealth({ ...base, integrity_protection: 'signed', integrity_signer: 'sha256:abc123' }, []).detail).toContain('signed by sha256:abc123');
    expect(runHealth({ ...base, ended_at: null, integrity: 'live' }, [])).toMatchObject({ label: 'Running' });
    expect(runHealth(base, [event(1, 'policy', 'approval.decision', 'denied')])).toMatchObject({ label: 'Blocked' });
    expect(runHealth(base, [event(1, 'policy', 'approval.request', 'pending')])).toMatchObject({ label: 'Awaiting approval' });
  });

  it('reports an abandoned recording instead of a running one', () => {
    const abandoned: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: null,
      exit_code: null, journal: null, integrity: 'abandoned',
      integrity_detail: 'The recorder is no longer running. Run `premier recover /traces/a.atrace` to finalize this trace.'
    };
    expect(runHealth(abandoned, [])).toEqual({
      label: 'Abandoned',
      tone: 'warning',
      detail: 'The recorder is no longer running. Run `premier recover /traces/a.atrace` to finalize this trace.'
    });
    // Nobody is left to answer a pending request or to keep the run going.
    expect(runHealth(abandoned, [event(1, 'policy', 'approval.request', 'pending')])).toMatchObject({ label: 'Abandoned' });
    expect(runHealth({ ...abandoned, integrity_detail: null }, []).detail).toContain('premier recover');
  });

  it('resolves pending approvals against a later decision', () => {
    const base: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '2026-01-01',
      exit_code: 0, journal: null, integrity: 'verified'
    };
    const request = { ...event(1, 'claude', 'approval.request', 'pending'), correlation_id: 'toolu_1' };
    const decision = { ...event(2, 'claude', 'approval.decision', 'approved'), correlation_id: 'toolu_1' };
    expect(awaitingApprovals([request])).toEqual([request]);
    expect(awaitingApprovals([request, decision])).toEqual([]);
    expect(runHealth(base, [request, decision])).toMatchObject({ label: 'Passed' });
    expect(summarizeAgents([request, decision])[0].status).toBe('ok');
    expect(summarizeAgents([request])[0].status).toBe('pending');

    // An approved/denied event of any kind on the same span settles the request too.
    const spanRequest = { ...event(3, 'claude', 'approval.request', 'pending'), span_id: 'span-approval' };
    const spanDenied = { ...event(4, 'claude', 'tool.result', 'denied'), span_id: 'span-approval' };
    expect(awaitingApprovals([spanRequest, spanDenied])).toEqual([]);

    // Unrelated, earlier, or still-undecided events do not.
    const other = { ...event(5, 'claude', 'approval.decision', 'approved'), correlation_id: 'toolu_2' };
    const earlier = { ...event(0, 'claude', 'approval.decision', 'approved'), correlation_id: 'toolu_1' };
    const stillPending = { ...event(6, 'claude', 'approval.decision', 'pending'), correlation_id: 'toolu_1' };
    const running = { ...event(7, 'claude', 'tool.invocation', 'running'), correlation_id: 'toolu_1' };
    expect(awaitingApprovals([earlier, request, other, stillPending, running])).toEqual([request, stillPending]);
    expect(runHealth(base, [earlier, request, other])).toMatchObject({ label: 'Awaiting approval', detail: '1 pending decision' });
    // Requests that carry no identity cannot be matched and stay pending.
    expect(awaitingApprovals([{ ...event(8, 'a', 'approval.request', 'pending'), span_id: '' }, { ...event(9, 'a', 'approval.decision', 'approved'), span_id: '' }])).toHaveLength(1);
  });

  it('treats an explicit native failure as an issue even when the status says ok', () => {
    const native = (value: unknown, correlation = '') => ({
      ...event(1, 'claude', 'tool.result'), correlation_id: correlation, payload_json: JSON.stringify({ native: value })
    });
    const failures = [
      { type: 'result', is_error: true, result: 'boom' },
      { type: 'tool_result', isError: true },
      { type: 'tool_result', tool_id: 't1', status: 'error' },
      { type: 'item.completed', item: { type: 'command_execution', exit_code: 2 } },
      { type: 'item.completed', item: { status: 'failed' } },
      { type: 'tool', part: { state: { status: 'error', error: 'exit 1' } } },
      { type: 'turn', error: { message: 'quota' } },
      { type: 'error', message: 'overloaded' },
      { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 't1', is_error: true }] } }
    ];
    for (const failure of failures) expect(isIssue(native(failure)), JSON.stringify(failure)).toBe(true);
    const healthy = [
      { type: 'result', is_error: false, result: 'done' },
      { type: 'item.completed', item: { exit_code: 0, status: 'completed' } },
      { type: 'item.started', item: { exit_code: null, status: 'in_progress' } },
      { type: 'tool_result', error: null },
      { type: 'tool_result', error: '' },
      { type: 'tool_use', input: { status: 'failed', is_error: true, exit_code: 1 } },
      { type: 'assistant', text: 'the build failed with an error' }
    ];
    for (const fine of healthy) expect(isIssue(native(fine)), JSON.stringify(fine)).toBe(false);
    // Without an adapter envelope the same fields are ordinary payload data.
    expect(isIssue({ ...event(1, 'sdk', 'tool.result'), payload_json: '{"is_error":true}' })).toBe(false);

    const failed = native(failures[0]);
    expect(categoryOf(failed)).toBe('error');
    expect(countByCategory([failed], 'error')).toBe(1);
    expect(filterEvents([failed, event(2, 'root', 'agent.turn')], { search: '', category: 'all', actorId: null, errorsOnly: true, correlationId: null })).toEqual([failed]);
    expect(summarizeAgents([failed])[0]).toMatchObject({ errors: 1, status: 'error' });
  });

  it('flags only the event that answers for a failed block of a shared native line', () => {
    const line = { type: 'user', message: { content: [
      { type: 'tool_result', tool_use_id: 't1', content: 'ok' },
      { type: 'tool_result', tool_use_id: 't2', is_error: true }
    ] } };
    const of = (correlation: string) => ({ ...event(1, 'claude', 'tool.result'), correlation_id: correlation, payload_json: JSON.stringify({ native: line }) });
    expect(isIssue(of('t1'))).toBe(false);
    expect(isIssue(of('t2'))).toBe(true);
    expect(isIssue(of(''))).toBe(true);
  });

  it('searches the timeline by event, span, parent span, and correlation ids', () => {
    const target = {
      ...event(1, 'coder', 'tool.execution'), event_id: '0198-EVENT-aa', span_id: 'span-Bravo',
      parent_span_id: 'parent-charlie', correlation_id: 'corr-delta'
    };
    const other = { ...event(2, 'coder', 'tool.execution'), event_id: 'zzz', span_id: 'yyy', parent_span_id: 'xxx', correlation_id: 'www' };
    const search = (query: string) => filterEvents([target, other], { search: query, category: 'all', actorId: null, errorsOnly: false, correlationId: null });
    for (const query of ['0198-event-AA', 'span-bravo', 'parent-charlie', 'corr-delta', '  CORR-DELTA ']) {
      expect(search(query), query).toEqual([target]);
    }
    expect(search('nothing-matches')).toEqual([]);
  });

  it('survives null and array payloads in event summaries', () => {
    expect(eventSummary({ ...event(1, 'root', 'agent.turn'), payload_json: 'null' })).toBe('null payload');
    expect(eventSummary({ ...event(2, 'root', 'agent.turn'), payload_json: '["a","b"]' })).toContain('a');
    expect(eventSummary({ ...event(3, 'root', 'agent.turn'), payload_json: '42' })).toBe('42');
  });


  it('extracts category-specific evidence instead of displaying the source', () => {
    const model = { ...event(1, 'researcher', 'model.response'), payload_json: JSON.stringify({ model: 'frontier-mini', summary: 'Found the divergence', tokens: 42 }) };
    const tool = { ...event(2, 'coder', 'tool.execution'), payload_json: JSON.stringify({ tool: 'rg', query: 'reconcileInvoice' }) };
    expect(eventSummary(model)).toBe('frontier-mini · Found the divergence · 42 tokens');
    expect(eventSummary(tool)).toBe('rg · query: reconcileInvoice');
  });

  it('summarizes shell wrappers and agent coordination without leaking command payloads', () => {
    const session = { ...event(1, 'root', 'session.start'), payload_json: JSON.stringify({ command: ['sh', '-c', 'post a very long collector harness'] }) };
    const delegation = { ...event(2, 'coordinator', 'agent.delegation'), payload_json: JSON.stringify({ delegates: ['auditor', 'reviewer'], execution: 'parallel' }) };
    const joined = { ...event(3, 'coordinator', 'agent.join'), payload_json: JSON.stringify({ joined: ['auditor', 'reviewer'], outcome: 'review complete' }) };
    expect(eventSummary(session)).toBe('Shell trace recording started');
    expect(eventSummary(delegation)).toBe('Delegated to auditor, reviewer');
    expect(eventSummary(joined)).toBe('Joined auditor, reviewer · review complete');
  });

  it('maps cross-actor parentage into causal lanes', () => {
    const parent = { ...event(1, 'coordinator', 'agent.delegation'), event_id: 'parent', span_id: 'delegate' };
    const child = { ...event(2, 'researcher', 'agent.spawn'), parent_event_id: 'parent', parent_span_id: 'delegate' };
    const layout = timelineLayout([parent, child]);
    expect(layout.lanes).toEqual(['coordinator', 'researcher']);
    expect(layout.events[1]).toMatchObject({ lane: 1, parentLane: 0, depth: 1, elapsedMs: 0 });
  });
});

function largeJournal(count: number): TraceEvent[] {
  const origin = Date.parse('2026-07-13T12:00:00.000Z');
  return Array.from({ length: count }, (_, index) => ({
    event_id: `big-${index}`, trace_id: 'big', sequence: index + 1,
    timestamp: new Date(origin + index * 10).toISOString(), kind: 'process.stdout', source: 'recorder', payload_json: '{"text":"x"}',
    actor_id: index % 2 ? 'worker' : 'root', actor_type: 'process', parent_event_id: '', span_id: '', parent_span_id: '',
    correlation_id: '', status: 'ok', duration_ms: index === count - 1 ? 500 : 0, links: []
  }));
}

describe('traceTimeBounds', () => {
  it('measures journals larger than the argument-spread limit', () => {
    // Math.min(...values) throws a RangeError above roughly 125k arguments.
    const bounds = traceTimeBounds(largeJournal(140_000));
    // The last event reports 500 ms of elapsed work; that ended when it was received.
    expect(bounds).toEqual({ start: Date.parse('2026-07-13T12:00:00.000Z'), span: 139_999 * 10 });
  }, 60_000);

  it('ignores unparseable timestamps and reports null when none are usable', () => {
    const [first, second] = largeJournal(2);
    expect(traceTimeBounds([])).toBeNull();
    expect(traceTimeBounds([{ ...first, timestamp: 'not a time' }])).toBeNull();
    expect(traceTimeBounds([{ ...first, timestamp: 'not a time' }, { ...second, duration_ms: 0 }])).toEqual({ start: Date.parse(second.timestamp), span: 1 });
  });
});

describe('process.spawn_failed', () => {
  // What `premier record` writes when the command cannot be started.
  const spawnFailed: TraceEvent = {
    ...event(2, 'root', 'process.spawn_failed', 'error'),
    source: 'premier', actor_type: 'process', span_id: 'command', parent_span_id: 'session',
    payload_json: JSON.stringify({ executable: 'no-such-agent', error: 'No such file or directory (os error 2)', exit_code: 127, success: false })
  };
  const scope = (category: 'process' | 'error' | 'tool') => ({ search: '', category, actorId: null, errorsOnly: false, correlationId: null });

  it('is a process-family issue', () => {
    expect(isIssue(spawnFailed)).toBe(true);
    expect(categoryOf(spawnFailed)).toBe('error');
    expect(filterEvents([spawnFailed], scope('process'))).toEqual([spawnFailed]);
    expect(filterEvents([spawnFailed], scope('error'))).toEqual([spawnFailed]);
    expect(filterEvents([spawnFailed], scope('tool'))).toEqual([]);
    expect(countByCategory([spawnFailed], 'process')).toBe(1);
    expect(countByCategory([spawnFailed], 'error')).toBe(1);
  });

  it('summarizes what failed to start and why instead of an exit status', () => {
    expect(eventSummary(spawnFailed)).toBe('Failed to start no-such-agent: No such file or directory (os error 2)');
    expect(eventSummary({ ...spawnFailed, payload_json: '{"exit_code":126}' })).toBe('Failed to start the command');
    // A real exit keeps its own wording.
    expect(eventSummary({ ...spawnFailed, kind: 'process.exit', payload_json: '{"exit_code":127}' })).toBe('Exited with status 127');
  });
});

describe('review findings: categories, search, clock, and terminal text', () => {
  const none = { search: '', category: 'all' as const, actorId: null, errorsOnly: false, correlationId: null };

  it('files kinds by a documented, case-insensitive prefix and keeps unknown ones out of agents', () => {
    const family = (kind: string) => familyOf(event(1, 'a', kind));
    expect(family('Tool.Call')).toBe('tool');
    expect(family('MODEL.response')).toBe('model');
    expect(family('llm.completion')).toBe('model');
    expect(family('mcp.request')).toBe('tool');
    expect(family('session.start')).toBe('process');
    expect(family('adapter.diagnostic')).toBe('process');
    expect(family('billing.charge')).toBe('other');
    expect(family('constructor.x')).toBe('other');
    expect(family('heartbeat')).toBe('other');
    const custom = event(2, 'a', 'billing.charge');
    expect(filterEvents([custom], { ...none, category: 'agent' })).toEqual([]);
    expect(filterEvents([custom], { ...none, category: 'other' })).toEqual([custom]);
    expect(countByCategory([custom], 'other')).toBe(1);
  });

  it('searches payload text as it is displayed, plus parent ids and links', () => {
    const output = {
      ...event(1, 'root', 'process.terminal'), parent_event_id: 'cause-77', links: ['ref-alpha'],
      payload_json: JSON.stringify({ text: '\u001b[31mbuild "failed"\u001b[0m\nline two' })
    };
    const other = event(2, 'root', 'process.terminal');
    const search = (query: string) => filterEvents([output, other], { ...none, search: query });
    for (const query of ['build "failed"', 'failed"\nline two', 'cause-77', 'REF-ALPHA']) {
      expect(search(query), query).toEqual([output]);
    }
  });

  it('shows terminal output without control sequences', () => {
    const chunk = { ...event(1, 'root', 'process.terminal'), payload_json: JSON.stringify({ text: '\u001b]0;title\u0007\u001b[1;32mok\u001b[0m done\r\n' }) };
    expect(eventSummary(chunk)).toBe('ok done');
    expect(stripControlSequences('plain text')).toBe('plain text');
  });

  it('measures elapsed time and causal depth against the whole run, not the filtered rows', () => {
    const at = (second: number) => `2026-07-13T12:00:0${second}.000Z`;
    const first = { ...event(1, 'lead', 'agent.turn'), event_id: 'a', span_id: 'sa', timestamp: at(0) };
    const middle = { ...event(2, 'lead', 'tool.call'), event_id: 'b', span_id: 'sb', parent_event_id: 'a', timestamp: at(2) };
    const last = { ...event(3, 'worker', 'tool.result'), event_id: 'c', span_id: 'sc', parent_event_id: 'b', timestamp: at(5) };
    const layout = timelineLayout([last], [first, middle, last]);
    expect(layout.events[0]).toMatchObject({ depth: 2, elapsedMs: 5000 });
    expect(timelineLayout([first, middle, last]).events.map((row) => row.depth)).toEqual([0, 1, 2]);
  });

  it('ends the run clock at the last received event and skips timestamps it cannot place', () => {
    const [first, second] = largeJournal(2);
    expect(traceTimeBounds([first, { ...second, duration_ms: 60_000 }])).toEqual({ start: Date.parse(first.timestamp), span: 10 });
    expect(traceTimeBounds([first, { ...second, timestamp: 'garbage' }])).toEqual({ start: Date.parse(first.timestamp), span: 1 });
  });

  it('names a locked or unsupported trace instead of calling it running', () => {
    const base = { format_version: 0, trace_id: 'locked:a.atrace', command: [], started_at: '2026-01-01T00:00:00Z', ended_at: null, exit_code: null, journal: null };
    expect(runHealth({ ...base, integrity: 'locked', integrity_detail: 'No key file was given.' }, [])).toMatchObject({ label: 'Locked', detail: 'No key file was given.' });
    expect(runHealth({ ...base, integrity: 'unsupported' }, [])).toMatchObject({ label: 'Unsupported', tone: 'warning' });
  });
});
