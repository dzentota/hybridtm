import { useCallback } from 'react'
import ELK, { type ElkExtendedEdge, type ElkNode } from 'elkjs/lib/elk.bundled.js'
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

function elkChild(n: StudioNode): ElkNode {
  return {
    id: n.id,
    width: (n.measured?.width as number | undefined) ?? DEFAULT_WIDTH,
    height: (n.measured?.height as number | undefined) ?? DEFAULT_HEIGHT,
  }
}

/** Boundaries are real compound nodes in the ELK graph — not a flat layout
 * re-fit with a bounding box afterwards. That earlier approach laid every
 * component out as one flat graph with no notion of "these belong
 * together," so the layered algorithm was free to interleave components
 * from different boundaries into the same layer/column; the bounding boxes
 * computed after the fact from that interleaved layout then overlapped
 * each other even though each box was individually correct for its own
 * members. Giving ELK the actual nesting (each boundary's members as its
 * `children`) makes it reserve real, non-overlapping space for each
 * container during layout, same as it does for any other compound node —
 * this is what ELK's hierarchical layout is for. Still only one level
 * deep, matching the one level of nesting the canvas itself supports. */
export function useElkLayout() {
  const runLayout = useCallback(async () => {
    const { nodes, edges } = useModelStore.getState()
    const componentNodes = nodes.filter((n) => n.type === 'component')
    const boundaryNodes = nodes.filter((n) => n.type === 'boundary')
    if (componentNodes.length === 0) return

    const parentOf = new Map(componentNodes.map((n) => [n.id, n.parentId]))

    // An edge belongs in the `edges` array of its endpoints' closest common
    // ancestor (ELK's hierarchical-edge convention) — here, either the
    // boundary both endpoints share, or the root if they don't share one.
    const rootEdges: ElkExtendedEdge[] = []
    const boundaryEdges = new Map<string, ElkExtendedEdge[]>()
    for (const e of edges) {
      const sourceParent = parentOf.get(e.source)
      const targetParent = parentOf.get(e.target)
      const elkEdge: ElkExtendedEdge = { id: e.id, sources: [e.source], targets: [e.target] }
      if (sourceParent && sourceParent === targetParent) {
        const list = boundaryEdges.get(sourceParent) ?? []
        list.push(elkEdge)
        boundaryEdges.set(sourceParent, list)
      } else {
        rootEdges.push(elkEdge)
      }
    }

    const orphanComponents = componentNodes.filter((n) => !n.parentId)
    const boundaryChildren: ElkNode[] = boundaryNodes.map((b) => ({
      id: b.id,
      layoutOptions: {
        'elk.padding': `[top=${BOUNDARY_PADDING},left=${BOUNDARY_PADDING},bottom=${BOUNDARY_PADDING},right=${BOUNDARY_PADDING}]`,
      },
      children: componentNodes.filter((n) => n.parentId === b.id).map(elkChild),
      edges: boundaryEdges.get(b.id) ?? [],
    }))

    const graph: ElkNode = {
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'RIGHT',
        'elk.spacing.nodeNode': '60',
        'elk.layered.spacing.nodeNodeBetweenLayers': '90',
        // Recommended whenever edges cross between hierarchy levels (any
        // root-level edge touching a boundary's member does) — without it
        // ELK lays each container out in isolation and the outer layout
        // ignores those edges entirely.
        'elk.hierarchyHandling': 'INCLUDE_CHILDREN',
      },
      children: [...orphanComponents.map(elkChild), ...boundaryChildren],
      edges: rootEdges,
    }

    let layouted: ElkNode
    try {
      layouted = await elk.layout(graph)
    } catch (err) {
      console.error('ELK layout failed', err)
      return
    }
    if (!layouted.children) return

    const boundaryIds = new Set(boundaryNodes.map((b) => b.id))
    const boundaryResult = new Map<string, ElkNode>()
    const rootComponentAbs = new Map<string, { x: number; y: number }>()
    for (const child of layouted.children) {
      if (boundaryIds.has(child.id)) boundaryResult.set(child.id, child)
      else rootComponentAbs.set(child.id, { x: child.x ?? 0, y: child.y ?? 0 })
    }

    useModelStore.getState().setNodes((nds) =>
      nds.map((n): StudioNode => {
        if (n.type === 'boundary') {
          const result = boundaryResult.get(n.id)
          if (!result) return n
          return {
            ...n,
            position: { x: result.x ?? 0, y: result.y ?? 0 },
            style: { ...n.style, width: result.width ?? n.style?.width, height: result.height ?? n.style?.height },
          }
        }
        if (n.parentId) {
          // ELK positions a compound node's children relative to that
          // node's own origin — exactly xyflow's convention for a node
          // with parentId, so no manual offset math is needed here.
          const parentResult = boundaryResult.get(n.parentId)
          const child = parentResult?.children?.find((c) => c.id === n.id)
          return child ? { ...n, position: { x: child.x ?? 0, y: child.y ?? 0 } } : n
        }
        const abs = rootComponentAbs.get(n.id)
        return abs ? { ...n, position: abs } : n
      }),
    )
  }, [])

  return { runLayout }
}
