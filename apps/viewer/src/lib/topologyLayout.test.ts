import { expect, it } from 'vitest';
import { COLUMN_GUTTER, MAX_ROWS, NODE_WIDTH, edgePath, layoutTopology } from './topologyLayout';

const numbers = (path: string) => path.match(/-?\d+(\.\d+)?/g)!.map(Number);

it('spaces role columns a full card plus a gutter apart', () => {
  const layout = layoutTopology([
    { id: 'root', type: 'process' }, { id: 'db', type: 'system' }, { id: 'lead', type: 'agent' },
    { id: 'worker', type: 'subagent' }, { id: 'reviewer', type: 'human' }
  ]);
  const xs = ['root', 'db', 'lead', 'worker', 'reviewer'].map((id) => layout.positions.get(id)!.x);
  for (let index = 1; index < xs.length; index += 1) expect(xs[index] - xs[index - 1]).toBeGreaterThanOrEqual(NODE_WIDTH + COLUMN_GUTTER);
  expect(layout.width).toBeGreaterThanOrEqual(xs[4] + NODE_WIDTH / 2);
});

it('wraps a large fan-out into several columns instead of one unbounded stack', () => {
  const actors = Array.from({ length: 20 }, (_, index) => ({ id: `worker-${index}`, type: 'subagent' as const }));
  const layout = layoutTopology(actors);
  const columns = new Set([...layout.positions.values()].map((position) => position.x));
  expect(columns.size).toBe(Math.ceil(20 / MAX_ROWS));
  expect(layout.height).toBeLessThanOrEqual(MAX_ROWS * 138 + 72);
  const keys = new Set([...layout.positions.values()].map((position) => `${position.x}:${position.y}`));
  expect(keys.size).toBe(20);
});

it('routes an edge between two actors of one column outside the cards', () => {
  const [, , c1x, , c2x] = numbers(edgePath({ x: 300, y: 100 }, { x: 300, y: 300 }));
  expect(c1x).toBeGreaterThan(300 + NODE_WIDTH / 2);
  expect(c2x).toBeGreaterThan(300 + NODE_WIDTH / 2);
  expect(c1x).toBeLessThan(300 + NODE_WIDTH / 2 + COLUMN_GUTTER);
  // The way back uses the other side, so the two never coincide.
  const [startX] = numbers(edgePath({ x: 300, y: 300 }, { x: 300, y: 100 }));
  expect(startX).toBe(300 - NODE_WIDTH / 2);
});

it('offsets opposite edges between the same two actors', () => {
  const a = { x: 100, y: 100 };
  const b = { x: 400, y: 200 };
  const out = numbers(edgePath(a, b, true));
  const back = numbers(edgePath(b, a, true));
  // Out leaves A above the centre line; back arrives at A below it.
  expect(out[1]).toBeLessThan(a.y);
  expect(back[back.length - 1]).toBeGreaterThan(a.y);
  expect(numbers(edgePath(a, b))[1]).toBe(a.y);
});
