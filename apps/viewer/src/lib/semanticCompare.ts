import { modelCallUsage } from './modelUsage';
import { toolFromNative } from './nativePayload';
import type { TraceEvent } from './types';

/**
 * Semantic comparison of two traces. This is the viewer's copy of `premier diff`
 * (`crates/premier-cli/src/evidence.rs`); the two are held to the same results by the cases in
 * `crates/premier-cli/tests/fixtures/diff/semantic-diff-cases.json`, which both test suites run.
 * Change one and the other must follow.
 */

/** `moved`: the same semantic event at a different place in the order. */
export type ComparisonStatus = 'added' | 'removed' | 'changed' | 'moved' | 'unchanged';

export interface FieldChange {
  field: string;
  before: unknown;
  after: unknown;
}

export interface NumericDelta {
  before: number;
  after: number;
  delta: number;
}

export interface ComparisonItem {
  key: string;
  status: ComparisonStatus;
  /** The event, or the first event of a captured output stream. */
  baseline: TraceEvent | null;
  current: TraceEvent | null;
  changes: FieldChange[];
  deltas: {
    durationMs: NumericDelta | null;
    totalTokens: NumericDelta | null;
    costUsd: NumericDelta | null;
  };
}

export interface TraceComparison {
  items: ComparisonItem[];
  counts: Record<ComparisonStatus, number>;
  /** The first item, in trace order, at which the traces stop agreeing. */
  firstDivergence: { index: number; item: ComparisonItem } | null;
  /** `per_key` when the traces differ in too many places to align in order. */
  alignment: 'ordered' | 'per_key';
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function compactIdentity(value: unknown): string {
  return (typeof value === 'string' ? value.trim() : JSON.stringify(value) ?? '').toLowerCase();
}

/** A cross-run identity: intentionally excludes generated event/span/correlation ids. */
export function semanticEventKey(event: TraceEvent): string {
  const payload = eventPayloadValue(event);
  const fields = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
  let discriminator: unknown;
  if (event.kind.startsWith('tool.')) {
    discriminator = fields.tool ?? fields.name ?? fields.command;
    // Adapter events recorded without `payload.tool` are keyed by the provider's own tool name.
    const native = fields.native;
    if ((discriminator === undefined || discriminator === null) && native && typeof native === 'object' && !Array.isArray(native)) {
      discriminator = toolFromNative(native) ?? undefined;
    }
  }
  else if (event.kind.startsWith('approval.')) discriminator = fields.operation ?? fields.action;
  // Adapter subagent actors end in the provider's generated tool-call id, which differs per run.
  let actor = event.actor_id.trim();
  const subagent = actor.indexOf(':subagent:');
  if (subagent >= 0 && event.source.startsWith('adapter.')) actor = `${actor.slice(0, subagent)}:subagent`;
  return `${event.kind.trim().toLowerCase()}:${(actor || 'root').toLowerCase()}${
    discriminator === undefined || discriminator === null ? '' : `:${compactIdentity(discriminator)}`}`;
}

/** The payload as stored: unlike `eventPayload`, scalars and arrays are not wrapped. */
function eventPayloadValue(event: TraceEvent): Json {
  try {
    return JSON.parse(event.payload_json) as Json;
  } catch {
    return null;
  }
}

function normalizedKey(key: string): string {
  return key.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

const GENERATED_KEYS = new Set(['eventid', 'traceid', 'spanid', 'parentspanid', 'parenteventid', 'correlationid', 'timestamp', 'createdat']);
/** Ids a provider CLI generates per run; only ignored inside an adapter's `native` copy. */
const PROVIDER_GENERATED_KEYS = new Set(['id', 'uuid', 'sessionid', 'threadid', 'messageid', 'requestid', 'itemid', 'callid', 'toolid', 'tooluseid', 'toolcallid', 'parenttooluseid']);

function comparableValue(value: Json, native: boolean): Json {
  if (Array.isArray(value)) return value.map((item) => comparableValue(item, native));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !GENERATED_KEYS.has(normalizedKey(key)) && !(native && PROVIDER_GENERATED_KEYS.has(normalizedKey(key))))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, item]) => [key, comparableValue(item, native || key === 'native')]));
}

function flatten(prefix: string, value: Json, output: Map<string, Json>): void {
  if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length > 0) {
    for (const [key, item] of Object.entries(value)) flatten(prefix ? `${prefix}.${key}` : key, item, output);
  } else {
    output.set(prefix, value);
  }
}

const TERMINAL_STREAMS = new Set(['process.stdout', 'process.stderr', 'process.terminal']);

/** The text of a stream as lines, with CRLF read as LF. */
function streamLines(text: string): string[] {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** One thing a comparison aligns: an event, or all the output of one stream. */
interface Unit {
  event: TraceEvent;
  key: string;
  fields: Map<string, Json>;
  /** Set for a stream: its whole text, as lines. */
  lines: string[] | null;
  eventIds: string[];
  content: string;
}

function eventFields(event: TraceEvent): Map<string, Json> {
  const fields = new Map<string, Json>([
    ['status', event.status],
    ['source', event.source],
    ['actor_type', event.actor_type],
    ['duration_ms', event.duration_ms]
  ]);
  const payload = comparableValue(eventPayloadValue(event), false);
  // The recorder's collector listens on a random port for each run.
  if (event.kind === 'session.start' && payload && typeof payload === 'object' && !Array.isArray(payload)) delete payload.instrumentation;
  flatten('payload', payload, fields);
  return fields;
}

function unitContent(fields: Map<string, Json>, lines: string[] | null): string {
  const sorted = [...fields.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify(sorted) + (lines ? `\n${lines.join('\n')}` : '');
}

/** Events as units, in order: one unit per output stream at the place of its first event. */
function diffUnits(events: TraceEvent[]): Unit[] {
  const units: Unit[] = [];
  const streams = new Map<string, { index: number; text: string }>();
  for (const event of events) {
    const key = semanticEventKey(event);
    if (TERMINAL_STREAMS.has(event.kind)) {
      const payload = eventPayloadValue(event);
      const text = payload && typeof payload === 'object' && !Array.isArray(payload) && typeof payload.text === 'string' ? payload.text : '';
      const stream = streams.get(key);
      if (stream) {
        stream.text += text;
        units[stream.index].eventIds.push(event.event_id);
        continue;
      }
      streams.set(key, { index: units.length, text });
      units.push({
        event,
        key,
        fields: new Map<string, Json>([['source', event.source], ['actor_type', event.actor_type]]),
        lines: [],
        eventIds: [event.event_id],
        content: ''
      });
    } else {
      units.push({ event, key, fields: eventFields(event), lines: null, eventIds: [event.event_id], content: '' });
    }
  }
  for (const stream of streams.values()) units[stream.index].lines = streamLines(stream.text);
  for (const unit of units) unit.content = unitContent(unit.fields, unit.lines);
  return units;
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

const LEADING_FIELDS = ['status', 'source', 'actor_type', 'duration_ms'];

function compareUnits(baseline: Unit, current: Unit): FieldChange[] {
  const changes: FieldChange[] = [];
  const rest = [...new Set([...baseline.fields.keys(), ...current.fields.keys()])]
    .filter((field) => !LEADING_FIELDS.includes(field))
    .sort();
  for (const field of [...LEADING_FIELDS, ...rest]) {
    const before = baseline.fields.get(field) ?? null;
    const after = current.fields.get(field) ?? null;
    if (!same(before, after)) changes.push({ field, before, after });
  }
  if (baseline.lines && current.lines && !same(baseline.lines, current.lines)) {
    const before = baseline.lines;
    const after = current.lines;
    if (before.length !== after.length) changes.push({ field: 'text.lines', before: before.length, after: after.length });
    let line = 0;
    while (line < before.length && line < after.length && before[line] === after[line]) line += 1;
    changes.push({ field: `text.line[${line + 1}]`, before: before[line] ?? null, after: after[line] ?? null });
  }
  return changes;
}

/** Edit distance beyond which an ordered alignment is not attempted. */
const MAX_ALIGNMENT_EDITS = 2_000;
const UNREACHED = Number.MIN_SAFE_INTEGER;

/** See `furthest_step` in evidence.rs. */
function furthestStep(downFrom: number, rightFrom: number, k: number, n: number, m: number): { x: number; down: boolean } | null {
  const down = downFrom !== UNREACHED && downFrom - k <= m ? downFrom : null;
  const right = rightFrom !== UNREACHED && rightFrom < n ? rightFrom + 1 : null;
  if (down !== null && right !== null && down >= right) return { x: down, down: true };
  if (right !== null) return { x: right, down: false };
  if (down !== null) return { x: down, down: true };
  return null;
}

function middleSubsequence(a: number[], b: number[]): Array<[number, number]> | null {
  const n = a.length;
  const m = b.length;
  if (n === 0 || m === 0) return [];
  const limit = Math.min(n + m, MAX_ALIGNMENT_EDITS);
  const offset = limit + 1;
  const furthest = new Array<number>(2 * limit + 3).fill(UNREACHED);
  furthest[offset + 1] = 0;
  const rounds: number[][] = [];
  let reached = -1;
  search: for (let d = 0; d <= limit; d += 1) {
    rounds.push(furthest.slice(offset - d - 1, offset + d + 2));
    for (let k = -d; k <= d; k += 2) {
      const step = furthestStep(furthest[offset + k + 1], furthest[offset + k - 1], k, n, m);
      if (!step) {
        furthest[offset + k] = UNREACHED;
        continue;
      }
      let x = step.x;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x += 1;
        y += 1;
      }
      furthest[offset + k] = x;
      if (x === n && y === m) {
        reached = d;
        break search;
      }
    }
  }
  if (reached < 0) return null;
  const pairs: Array<[number, number]> = [];
  let x = n;
  let y = m;
  for (let d = reached; d >= 0; d -= 1) {
    const round = rounds[d];
    const at = (k: number) => round[k + d + 1];
    const k = x - y;
    const step = furthestStep(at(k + 1), at(k - 1), k, n, m);
    if (!step) return null;
    while (x > step.x) {
      x -= 1;
      y -= 1;
      pairs.push([x, y]);
    }
    if (step.down) y -= 1;
    else x -= 1;
  }
  return pairs.reverse();
}

/** A longest common subsequence as index pairs in order (Myers), or null when too different. */
function commonSubsequence(a: number[], b: number[]): Array<[number, number]> | null {
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix += 1;
  let suffix = 0;
  while (suffix < a.length - prefix && suffix < b.length - prefix && a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) suffix += 1;
  const middle = middleSubsequence(a.slice(prefix, a.length - suffix), b.slice(prefix, b.length - suffix));
  if (!middle) return null;
  const pairs: Array<[number, number]> = [];
  for (let index = 0; index < prefix; index += 1) pairs.push([index, index]);
  for (const [x, y] of middle) pairs.push([prefix + x, prefix + y]);
  for (let index = 0; index < suffix; index += 1) pairs.push([a.length - suffix + index, b.length - suffix + index]);
  return pairs;
}

type Slot = { baseline: number; current: number } | { baseline: number; current: null } | { baseline: null; current: number };

/** Align in order: first units equal in every compared field, then, between those, equal keys. */
function orderedAlignment(baseline: Unit[], current: Unit[]): Slot[] | null {
  const ids = new Map<string, number>();
  const id = (value: string) => {
    const known = ids.get(value);
    if (known !== undefined) return known;
    ids.set(value, ids.size);
    return ids.size - 1;
  };
  const exact = (units: Unit[]) => units.map((unit) => id(`${unit.key}\u0000${unit.content}`));
  const keys = (units: Unit[]) => units.map((unit) => id(unit.key));
  const exactA = exact(baseline);
  const exactB = exact(current);
  const keyA = keys(baseline);
  const keyB = keys(current);
  const anchors = commonSubsequence(exactA, exactB);
  if (!anchors) return null;
  anchors.push([baseline.length, current.length]);
  const slots: Slot[] = [];
  let fromA = 0;
  let fromB = 0;
  for (const [anchorA, anchorB] of anchors) {
    const pairs = commonSubsequence(keyA.slice(fromA, anchorA), keyB.slice(fromB, anchorB));
    if (!pairs) return null;
    let a = fromA;
    let b = fromB;
    for (const [pairA, pairB] of [...pairs.map(([x, y]) => [fromA + x, fromB + y] as [number, number]), [anchorA, anchorB] as [number, number]]) {
      for (; a < pairA; a += 1) slots.push({ baseline: a, current: null });
      for (; b < pairB; b += 1) slots.push({ baseline: null, current: b });
      if (pairA < baseline.length) slots.push({ baseline: pairA, current: pairB });
      a = pairA + 1;
      b = pairB + 1;
    }
    fromA = anchorA + 1;
    fromB = anchorB + 1;
  }
  return slots;
}

/** The fallback: the n-th baseline unit of a key with the n-th current one, whatever their order. */
function perKeyAlignment(baseline: Unit[], current: Unit[]): Slot[] {
  const groups = new Map<string, number[]>();
  current.forEach((unit, index) => groups.set(unit.key, [...(groups.get(unit.key) ?? []), index]));
  const used = new Set<number>();
  const slots: Slot[] = [];
  baseline.forEach((unit, index) => {
    const paired = groups.get(unit.key)?.shift();
    if (paired === undefined) slots.push({ baseline: index, current: null });
    else {
      used.add(paired);
      slots.push({ baseline: index, current: paired });
    }
  });
  current.forEach((_, index) => {
    if (!used.has(index)) slots.push({ baseline: null, current: index });
  });
  return slots;
}

interface Aligned {
  baseline: number | null;
  current: number | null;
  moved: boolean;
}

/** Pair leftover removed and added units with one key: one event that moved. Equal content first. */
function pairMoved(slots: Slot[], baseline: Unit[], current: Unit[]): Aligned[] {
  const exact = (unit: Unit) => `${unit.key}\u0000${unit.content}`;
  const added = slots.filter((slot) => slot.baseline === null).map((slot) => slot.current as number);
  const removedExact = new Map<string, number[]>();
  const removedByKey = new Map<string, number[]>();
  if (added.length) {
    for (const slot of slots) {
      if (slot.current !== null || slot.baseline === null) continue;
      const unit = baseline[slot.baseline];
      removedExact.set(exact(unit), [...(removedExact.get(exact(unit)) ?? []), slot.baseline]);
      removedByKey.set(unit.key, [...(removedByKey.get(unit.key) ?? []), slot.baseline]);
    }
  }
  const partner = new Map<number, number>();
  const taken = new Set<number>();
  for (const index of added) {
    const found = removedExact.get(exact(current[index]))?.shift();
    if (found !== undefined) {
      taken.add(found);
      partner.set(index, found);
    }
  }
  for (const index of added) {
    if (partner.has(index)) continue;
    const candidates = removedByKey.get(current[index].key) ?? [];
    while (candidates.length) {
      const found = candidates.shift() as number;
      if (!taken.has(found)) {
        taken.add(found);
        partner.set(index, found);
        break;
      }
    }
  }
  const aligned: Aligned[] = [];
  for (const slot of slots) {
    if (slot.baseline !== null && slot.current !== null) aligned.push({ baseline: slot.baseline, current: slot.current, moved: false });
    else if (slot.baseline !== null) {
      if (!taken.has(slot.baseline)) aligned.push({ baseline: slot.baseline, current: null, moved: false });
    } else {
      const index = slot.current as number;
      aligned.push({ baseline: partner.get(index) ?? null, current: index, moved: partner.has(index) });
    }
  }
  return aligned;
}

/** Put each output stream at the place of its first output; streams pair by key alone. */
function placeStreams(aligned: Aligned[], baseline: Unit[], current: Unit[]): void {
  const streams = (units: Unit[]) => units.map((unit, index) => (unit.lines ? index : -1)).filter((index) => index >= 0);
  const before = streams(baseline);
  const after = streams(current);
  const items: Aligned[] = after.map((index) => ({
    baseline: before.find((candidate) => baseline[candidate].key === current[index].key) ?? null,
    current: index,
    moved: false
  }));
  for (const index of before) {
    if (!items.some((item) => item.baseline === index)) items.push({ baseline: index, current: null, moved: false });
  }
  for (const stream of items) {
    const position = aligned.findIndex((item) => {
      if (stream.current !== null && item.current !== null) return item.current > stream.current;
      if (stream.baseline !== null && item.baseline !== null) return item.baseline > stream.baseline;
      return false;
    });
    aligned.splice(position < 0 ? aligned.length : position, 0, stream);
  }
}

/** Where a causal reference points: nothing, something outside the trace, or units of it. */
type Reference = { kind: 'none' } | { kind: 'unresolved' } | { kind: 'units'; units: number[] };

interface Side {
  unit: Unit;
  /** Index of `unit` in `units`. */
  index: number;
  units: Unit[];
  byEventId: Map<string, number[]>;
  bySpan: Map<string, number[]>;
  byCorrelation: Map<string, number[]>;
  items: Array<number | null>;
}

function references(units: Unit[]): Pick<Side, 'byEventId' | 'bySpan' | 'byCorrelation'> {
  const byEventId = new Map<string, number[]>();
  const bySpan = new Map<string, number[]>();
  const byCorrelation = new Map<string, number[]>();
  const add = (map: Map<string, number[]>, id: string, index: number) => {
    const known = map.get(id);
    if (known) known.push(index);
    else map.set(id, [index]);
  };
  units.forEach((unit, index) => {
    for (const eventId of unit.eventIds) if (!byEventId.has(eventId)) byEventId.set(eventId, [index]);
    if (unit.event.span_id) add(bySpan, unit.event.span_id, index);
    if (unit.event.correlation_id) add(byCorrelation, unit.event.correlation_id, index);
  });
  return { byEventId, bySpan, byCorrelation };
}

function resolve(map: Map<string, number[]>, id: string): Reference {
  if (!id) return { kind: 'none' };
  const units = map.get(id);
  return units ? { kind: 'units', units } : { kind: 'unresolved' };
}

function describe(side: Side, reference: Reference): unknown {
  if (reference.kind === 'none') return null;
  if (reference.kind === 'unresolved') return { unresolved: true };
  const first = side.units[reference.units[0]];
  return { key: first.key, sequence: first.event.sequence };
}

/** The diff items a reference leads to; `null` when there is nothing to follow. */
function itemsOf(side: Side, reference: Reference): number[] | null {
  if (reference.kind === 'none') return [];
  if (reference.kind === 'unresolved') return null;
  return reference.units.map((unit) => side.items[unit]).filter((item): item is number => item !== null);
}

/**
 * Ids are generated per run, so a reference is followed to the events it names, and two
 * references agree when they lead to a common item. A correlation is compared through the other
 * events that share it.
 */
function causalChanges(baseline: Side, current: Side): FieldChange[] {
  const changes: FieldChange[] = [];
  const compare = (field: string, before: Reference, after: Reference, group: boolean) => {
    let beforeItems = itemsOf(baseline, before);
    let afterItems = itemsOf(current, after);
    if (!beforeItems || !afterItems) return;
    const beforeStated = before.kind !== 'none';
    const afterStated = after.kind !== 'none';
    if (group) {
      beforeItems = beforeItems.filter((item) => item !== baseline.items[baseline.index]);
      afterItems = afterItems.filter((item) => item !== current.items[current.index]);
      if (beforeStated && afterStated && (!beforeItems.length || !afterItems.length)) return;
    }
    const others = afterItems;
    const agree = beforeStated === afterStated && (!beforeStated || beforeItems.some((item) => others.includes(item)));
    if (!agree) changes.push({ field, before: describe(baseline, before), after: describe(current, after) });
  };
  const before = baseline.unit.event;
  const after = current.unit.event;
  compare('parent_event', resolve(baseline.byEventId, before.parent_event_id), resolve(current.byEventId, after.parent_event_id), false);
  compare('parent_span', resolve(baseline.bySpan, before.parent_span_id), resolve(current.bySpan, after.parent_span_id), false);
  compare('correlation', resolve(baseline.byCorrelation, before.correlation_id), resolve(current.byCorrelation, after.correlation_id), true);
  const links = (side: Side) => {
    const linked: number[] = [];
    const described: unknown[] = [];
    for (const link of side.unit.event.links ?? []) {
      const reference = resolve(side.byEventId, link);
      const items = itemsOf(side, reference);
      if (!items) return null;
      linked.push(...items);
      described.push(describe(side, reference));
    }
    return { items: [...new Set(linked)].sort((a, b) => a - b), described };
  };
  const beforeLinks = links(baseline);
  const afterLinks = links(current);
  if (beforeLinks && afterLinks && !same(beforeLinks.items, afterLinks.items)) {
    changes.push({ field: 'links', before: beforeLinks.described, after: afterLinks.described });
  }
  return changes;
}

function round(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function delta(before: number | null, after: number | null): NumericDelta | null {
  if (before === null || after === null || before === after) return null;
  return { before, after, delta: round(after - before) };
}

const NO_DELTAS = { durationMs: null, totalTokens: null, costUsd: null };

export function compareTraces(baselineInput: TraceEvent[], currentInput: TraceEvent[]): TraceComparison {
  const baseline = diffUnits([...baselineInput].sort((a, b) => a.sequence - b.sequence));
  const current = diffUnits([...currentInput].sort((a, b) => a.sequence - b.sequence));
  // Captured output is compared per stream and takes no part in the order.
  const events = (units: Unit[]) => units.map((unit, index) => (unit.lines ? -1 : index)).filter((index) => index >= 0);
  const baselineEvents = events(baseline);
  const currentEvents = events(current);
  const before = baselineEvents.map((index) => baseline[index]);
  const after = currentEvents.map((index) => current[index]);
  const ordered = orderedAlignment(before, after);
  const slots = (ordered ?? perKeyAlignment(before, after)).map((slot) => ({
    baseline: slot.baseline === null ? null : baselineEvents[slot.baseline],
    current: slot.current === null ? null : currentEvents[slot.current]
  }) as Slot);
  const aligned = pairMoved(slots, baseline, current);
  placeStreams(aligned, baseline, current);

  const baselineItems = new Array<number | null>(baseline.length).fill(null);
  const currentItems = new Array<number | null>(current.length).fill(null);
  aligned.forEach((item, index) => {
    if (item.baseline !== null) baselineItems[item.baseline] = index;
    if (item.current !== null) currentItems[item.current] = index;
  });
  const baselineSide = { units: baseline, items: baselineItems, ...references(baseline) };
  const currentSide = { units: current, items: currentItems, ...references(current) };

  const occurrences = new Map<string, number>();
  const counts: Record<ComparisonStatus, number> = { added: 0, removed: 0, changed: 0, moved: 0, unchanged: 0 };
  const items: ComparisonItem[] = aligned.map((item) => {
    const beforeUnit = item.baseline === null ? null : baseline[item.baseline];
    const afterUnit = item.current === null ? null : current[item.current];
    const unit = (afterUnit ?? beforeUnit) as Unit;
    const occurrence = (occurrences.get(unit.key) ?? 0) + 1;
    occurrences.set(unit.key, occurrence);
    const key = `${unit.key}#${occurrence}`;
    let status: ComparisonStatus;
    let changes: FieldChange[] = [];
    let deltas: ComparisonItem['deltas'] = NO_DELTAS;
    if (beforeUnit && afterUnit) {
      changes = compareUnits(beforeUnit, afterUnit);
      if (!beforeUnit.lines) {
        changes.push(...causalChanges(
          { unit: beforeUnit, index: item.baseline as number, ...baselineSide },
          { unit: afterUnit, index: item.current as number, ...currentSide }
        ));
        const beforeModel = modelCallUsage(beforeUnit.event);
        const afterModel = modelCallUsage(afterUnit.event);
        deltas = {
          durationMs: delta(beforeUnit.event.duration_ms, afterUnit.event.duration_ms),
          totalTokens: delta(beforeModel?.tokens.total ?? null, afterModel?.tokens.total ?? null),
          costUsd: delta(beforeModel?.costUsd ?? null, afterModel?.costUsd ?? null)
        };
      }
      status = item.moved ? 'moved' : changes.length ? 'changed' : 'unchanged';
    } else {
      status = beforeUnit ? 'removed' : 'added';
    }
    counts[status] += 1;
    return { key, status, baseline: beforeUnit?.event ?? null, current: afterUnit?.event ?? null, changes, deltas };
  });
  const first = items.findIndex((item) => item.status !== 'unchanged');
  return {
    items,
    counts,
    firstDivergence: first < 0 ? null : { index: first, item: items[first] },
    alignment: ordered ? 'ordered' : 'per_key'
  };
}
