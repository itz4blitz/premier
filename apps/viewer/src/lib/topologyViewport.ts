export interface TopologyPoint { x: number; y: number }
export interface TopologyViewport { width: number; height: number }
export interface TopologyFit { zoom: number; panX: number; panY: number }

/** Small enough that Fit can show a few hundred actors; below this the map is not readable anyway. */
export const MIN_ZOOM = 0.1;
export const MAX_ZOOM = 2;

const padding = 24;
const nodeHalfWidth = 108;
const nodeHalfHeight = 62;

/** Fit the occupied node bounds—not the unused logical canvas—into the stage. */
export function fitTopology(viewport: TopologyViewport, actors: TopologyPoint[]): TopologyFit {
  if (!actors.length || viewport.width <= 0 || viewport.height <= 0) return { zoom: 1, panX: 0, panY: 0 };

  let minX = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  for (const actor of actors) {
    minX = Math.min(minX, actor.x - nodeHalfWidth);
    maxX = Math.max(maxX, actor.x + nodeHalfWidth);
    minY = Math.min(minY, actor.y - nodeHalfHeight);
    maxY = Math.max(maxY, actor.y + nodeHalfHeight);
  }
  const contentWidth = Math.max(1, maxX - minX);
  const contentHeight = Math.max(1, maxY - minY);
  const availableWidth = Math.max(1, viewport.width - padding * 2);
  const availableHeight = Math.max(1, viewport.height - padding * 2);
  const zoom = Math.max(MIN_ZOOM, Math.min(1.25, availableWidth / contentWidth, availableHeight / contentHeight));
  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;

  return {
    zoom: Math.round(zoom * 1000) / 1000,
    panX: Math.round((viewport.width / 2 - centerX * zoom) * 10) / 10,
    panY: Math.round((viewport.height / 2 - centerY * zoom) * 10) / 10
  };
}
