import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import { isIssue, summarizeAgents } from './analysis';
import { childEvents } from './causal';
import { modelCallUsage } from './modelUsage';
import { payloadTool } from './nativePayload';
import RunOverview from './RunOverview.svelte';
import { compareTraces } from './semanticCompare';
import { eventPayload, type TraceEvent, type TraceManifest } from './types';

/**
 * The events `premier record --adapter claude` stores for the Claude fixture. The file is written
 * by the adapter itself and kept current by a Rust test (`claude_fixture_matches_its_checked_in_
 * normalized_events`), so these are real adapter output, not a hand-built imitation of it.
 */
const recorded = JSON.parse(readFileSync(
  resolve(__dirname, '../../../../crates/premier-cli/tests/fixtures/adapters/claude.normalized.json'),
  'utf8'
)) as Array<Omit<TraceEvent, 'payload_json' | 'trace_id' | 'timestamp'> & { payload: unknown }>;

const events: TraceEvent[] = recorded.map(({ payload, ...event }) => ({
  ...event,
  trace_id: 'adapter-trace',
  timestamp: `2026-07-15T12:00:${String(event.sequence).padStart(2, '0')}Z`,
  payload_json: JSON.stringify(payload)
}));

const manifest: TraceManifest = {
  format_version: 2, trace_id: 'adapter-trace', name: 'Claude adapter recording',
  command: ['claude', '-p', 'task', '--output-format', 'stream-json'],
  started_at: '2026-07-15T12:00:00Z', ended_at: '2026-07-15T12:00:20Z', exit_code: 0, journal: null
};

describe('a trace recorded through the Claude adapter', () => {
  it('is the adapter output the viewer is expected to read', () => {
    expect(events.length).toBeGreaterThan(10);
    expect(events.every((event) => event.source === 'adapter.claude.v1')).toBe(true);
    expect(events.map((event) => event.sequence)).toEqual(events.map((_, index) => index + 1));
  });

  it('names the tool of every tool event and flags the failed call only', () => {
    const tools = events.filter((event) => event.kind.startsWith('tool.'));
    expect(tools.length).toBeGreaterThan(5);
    for (const event of tools) expect(payloadTool(eventPayload(event)), `event ${event.sequence}`).toBeTruthy();
    expect(new Set(tools.map((event) => payloadTool(eventPayload(event))))).toEqual(new Set(['Read', 'Bash', 'Task', 'Grep']));
    const issues = events.filter(isIssue);
    expect(issues.map((event) => [event.kind, payloadTool(eventPayload(event))])).toEqual([['tool.result', 'Bash']]);
  });

  it('reads model usage and the subagent the adapter synthesized', () => {
    const first = events.find((event) => event.kind === 'model.response');
    expect(modelCallUsage(first!)?.tokens.total).toBe(25);
    const agents = summarizeAgents(events);
    expect(agents.map((agent) => agent.id).sort()).toEqual(['claude', 'claude:subagent:tool-3']);
    const spawn = events.find((event) => event.kind === 'agent.spawn');
    expect(eventPayload(spawn!).synthesized).toBe(true);
    // The spawning call's children are the spawn and the call's own result.
    expect(childEvents(events, spawn!.parent_event_id).map((event) => event.kind).sort()).toEqual(['agent.spawn', 'tool.result']);
  });

  it('compares clean against another run whose generated ids all differ', () => {
    const renamed = (id: string) => (id ? `other-${id}` : id);
    const rerun: TraceEvent[] = events.map((event) => ({
      ...event,
      trace_id: 'adapter-trace-2',
      event_id: renamed(event.event_id),
      parent_event_id: renamed(event.parent_event_id),
      links: event.links.map(renamed),
      // The provider's tool-call id is part of a subagent's actor id.
      actor_id: event.actor_id.replace('tool-3', 'tool-9')
    }));
    const comparison = compareTraces(events, rerun);
    expect(comparison.firstDivergence).toBeNull();
    expect(comparison.counts).toEqual({ added: 0, removed: 0, changed: 0, moved: 0, unchanged: events.length });
  });

  it('renders in the run overview', () => {
    render(RunOverview, { props: { trace: manifest, events, compact: false } });
    expect(document.body.textContent).toContain(`${events.length}`);
    expect(screen.queryByText(/NaN|undefined/)).not.toBeInTheDocument();
  });
});
