import { useCallback } from 'react'
import ELK, { type ElkNode } from 'elkjs/lib/elk.bundled.js'
import { useModelStore, type StudioNode } from '../store/model.store'

const DEFAULT_WIDTH = 200
const DEFAULT_HEIGHT = 90
const BOUNDARY_PADDING = 48

// Explicit `workerFactory` makes elkjs spawn a real browser Worker
// (public/elk-worker.min.js, copied from node_modules/elkjs/lib) instead of
// running the layered-graph algorithm synchronously on the main thread
// (T-7.14). Passing only `workerUrl` isn't enough — elk.bundled.js's default
// export tries to auto-wire a factory via the Node-only 'web-worker'
// package first and falls back to a synchronous shim when that's absent,
// which it always is in a browser bundle.
const elk = new ELK({
  workerUrl: '/elk-worker.min.js',
  workerFactory: (url?: string) => new Worker(url ?? '/elk-worker.min.js'),
})

/** Boundaries aren't part of the ELK graph (that'd need true hierarchical
 * layout) — every component is laid out as one flat graph, then each
 * boundary's box is re-fit around its children afterwards. Simpler than
 * hierarchy-aware ELK, correct for the one-level-deep nesting this app
 * supports today. */
export function useElkLayout() {
  const runLayout = useCallback(async () => {
    const { nodes, edges } = useModelStore.getState()
    const componentNodes = nodes.filter((n) => n.type === 'component')
    const boundaryNodes = nodes.filter((n) => n.type === 'boundary')
    if (componentNodes.length === 0) return

    const graph: ElkNode = {
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'RIGHT',
        'elk.spacing.nodeNode': '60',
        'elk.layered.spacing.nodeNodeBetweenLayers': '90',
      },
      children: componentNodes.map((n) => ({
        id: n.id,
        width: (n.measured?.width as number | undefined) ?? DEFAULT_WIDTH,
        height: (n.measured?.height as number | undefined) ?? DEFAULT_HEIGHT,
      })),
      edges: edges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
    }

    let layouted: ElkNode
    try {
      layouted = await elk.layout(graph)
    } catch (err) {
      console.error('ELK layout failed', err)
      return
    }
    if (!layouted.children) return

    const absoluteById = new Map<string, { x: number; y: number }>()
    for (const child of layouted.children) {
      absoluteById.set(child.id, { x: child.x ?? 0, y: child.y ?? 0 })
    }

    const boundaryBounds = new Map<string, { minX: number; minY: number; maxX: number; maxY: number }>()
    for (const n of componentNodes) {
      if (!n.parentId) continue
      const abs = absoluteById.get(n.id)
      if (!abs) continue
      const width = (n.measured?.width as number | undefined) ?? DEFAULT_WIDTH
      const height = (n.measured?.height as number | undefined) ?? DEFAULT_HEIGHT
      const bounds = boundaryBounds.get(n.parentId) ?? { minX: abs.x, minY: abs.y, maxX: abs.x + width, maxY: abs.y + height }
      bounds.minX = Math.min(bounds.minX, abs.x)
      bounds.minY = Math.min(bounds.minY, abs.y)
      bounds.maxX = Math.max(bounds.maxX, abs.x + width)
      bounds.maxY = Math.max(bounds.maxY, abs.y + height)
      boundaryBounds.set(n.parentId, bounds)
    }

    const boundaryPosition = new Map<string, { x: number; y: number }>()
    for (const b of boundaryNodes) {
      const bounds = boundaryBounds.get(b.id)
      const position = bounds
        ? { x: bounds.minX - BOUNDARY_PADDING, y: bounds.minY - BOUNDARY_PADDING }
        : b.position
      boundaryPosition.set(b.id, position)
    }

    useModelStore.getState().setNodes((nds) =>
      nds.map((n): StudioNode => {
        if (n.type === 'boundary') {
          const bounds = boundaryBounds.get(n.id)
          const position = boundaryPosition.get(n.id) ?? n.position
          if (!bounds) return { ...n, position }
          return {
            ...n,
            position,
            style: {
              ...n.style,
              width: bounds.maxX - bounds.minX + BOUNDARY_PADDING * 2,
              height: bounds.maxY - bounds.minY + BOUNDARY_PADDING * 2,
            },
          }
        }
        const abs = absoluteById.get(n.id)
        if (!abs) return n
        if (n.parentId) {
          const parentPos = boundaryPosition.get(n.parentId)
          if (parentPos) return { ...n, position: { x: abs.x - parentPos.x, y: abs.y - parentPos.y } }
        }
        return { ...n, position: abs }
      }),
    )
  }, [])

  return { runLayout }
}
