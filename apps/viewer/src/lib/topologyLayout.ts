import type { ActorRole } from './analysis';

export interface TopologyPosition { x: number; y: number }
export interface TopologyLayout {
  positions: Map<string, TopologyPosition>;
  width: number;
  height: number;
}

/** Card width in the map; keep in step with `.actor` in AgentTopology.svelte. */
export const NODE_WIDTH = 196;
/** Clear space between two columns of cards, where edges are drawn. */
export const COLUMN_GUTTER = 72;
export const COLUMN_PITCH = NODE_WIDTH + COLUMN_GUTTER;
export const ROW_PITCH = 138;
/** A role with more actors than this wraps into another column instead of one unbounded stack. */
export const MAX_ROWS = 6;

const MARGIN = 28;
const ROLE_ORDER: ActorRole[] = ['process', 'system', 'agent', 'subagent', 'human'];

/**
 * One column per role that has actors, left to right in `ROLE_ORDER`, each wrapped at `MAX_ROWS`.
 * Columns are a card plus a gutter apart, so no two cards touch and every edge has room to show.
 */
export function layoutTopology(actors: { id: string; type: ActorRole }[]): TopologyLayout {
  const columns: string[][] = [];
  for (const role of ROLE_ORDER) {
    const peers = actors.filter((actor) => actor.type === role).map((actor) => actor.id);
    for (let index = 0; index < peers.length; index += MAX_ROWS) columns.push(peers.slice(index, index + MAX_ROWS));
  }
  const tallest = Math.max(1, ...columns.map((column) => column.length));
  const height = Math.max(330, tallest * ROW_PITCH + 72);
  const width = Math.max(1, columns.length) * COLUMN_PITCH - COLUMN_GUTTER + MARGIN * 2;
  const positions = new Map<string, TopologyPosition>();
  columns.forEach((column, columnIndex) => {
    const x = MARGIN + NODE_WIDTH / 2 + columnIndex * COLUMN_PITCH;
    column.forEach((id, rowIndex) => positions.set(id, { x, y: ((rowIndex + 1) * height) / (column.length + 1) }));
  });
  return { positions, width, height };
}

/**
 * The curve for an edge from `source` to `target`. Edges between columns leave and enter on the
 * facing sides. Edges within one column bow out into the gutter beside it instead of running
 * under the cards. When the opposite edge is drawn too (`paired`), the two are offset to either
 * side of the centre line so both stay visible and clickable.
 */
export function edgePath(source: TopologyPosition, target: TopologyPosition, paired = false): string {
  const half = NODE_WIDTH / 2;
  if (Math.abs(target.x - source.x) < NODE_WIDTH) {
    // Same column: down the right-hand gutter, back up the left-hand one.
    const side = target.y >= source.y ? 1 : -1;
    const startX = source.x + side * half;
    const endX = target.x + side * half;
    const bow = side * (COLUMN_GUTTER - 16);
    return `M ${startX} ${source.y} C ${startX + bow} ${source.y}, ${endX + bow} ${target.y}, ${endX} ${target.y}`;
  }
  const forward = target.x >= source.x;
  const startX = source.x + (forward ? half : -half);
  const endX = target.x + (forward ? -half : half);
  const offset = paired ? (forward ? -12 : 12) : 0;
  const control = (startX + endX) / 2;
  return `M ${startX} ${source.y + offset} C ${control} ${source.y + offset}, ${control} ${target.y + offset}, ${endX} ${target.y + offset}`;
}
