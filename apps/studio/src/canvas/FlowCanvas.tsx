import { useCallback, useRef } from 'react'
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  addEdge,
  applyNodeChanges,
  applyEdgeChanges,
  type Connection,
  type NodeChange,
  type EdgeChange,
  type OnNodeDrag,
  useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useModelStore, absolutePosition, type StudioNode, type StudioEdge } from '../store/model.store'
import { ComponentNode } from './nodes/ComponentNode'
import { BoundaryNode } from './nodes/BoundaryNode'
import { DataFlowEdge } from './edges/DataFlowEdge'
import type { KbBundle } from '../api/types'

const nodeTypes = { component: ComponentNode, boundary: BoundaryNode }
const edgeTypes = { dataflow: DataFlowEdge }

function CanvasInner({ kb }: { kb: KbBundle | undefined }) {
  const { nodes, edges, setNodes, setEdges, select, selectEdge, addComponentFromKb } = useModelStore()
  const wrapperRef = useRef<HTMLDivElement>(null)
  const { screenToFlowPosition } = useReactFlow()

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => {
      // Pause undo-history recording while a drag is in progress so every
      // intermediate mouse-move position doesn't become its own undo step —
      // only the drag's final settled position does (T-7.13).
      const dragging = changes.some((c) => c.type === 'position' && c.dragging)
      const dragEnded = changes.some((c) => c.type === 'position' && c.dragging === false)
      if (dragging) useModelStore.temporal.getState().pause()
      if (dragEnded) useModelStore.temporal.getState().resume()
      setNodes((nds) => applyNodeChanges(changes, nds) as typeof nds)
    },
    [setNodes],
  )
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => setEdges((eds) => applyEdgeChanges(changes, eds) as typeof eds),
    [setEdges],
  )
  const onConnect = useCallback(
    (connection: Connection) =>
      setEdges((eds) => addEdge({ ...connection, type: 'dataflow', data: {} }, eds)),
    [setEdges],
  )
  const onSelectionChange = useCallback(
    ({ nodes: sel, edges: selEdges }: { nodes: StudioNode[]; edges: StudioEdge[] }) => {
      select(sel[0]?.id ?? null)
      selectEdge(sel.length === 0 ? selEdges[0]?.id ?? null : null)
    },
    [select, selectEdge],
  )

  // Smallest-area boundary match, not first-in-array-order: two boundaries
  // can legitimately overlap on screen (nothing stops a user from placing
  // one over another), and `.find()` picking whichever happens to sit
  // first in the node list — unrelated to z-order or which box the user
  // can actually see themselves dropping into — could silently parent a
  // component to the wrong one. The smallest matching box is the most
  // specific/innermost one, matching what a user visually aims for.
  const boundaryAt = useCallback(
    (point: { x: number; y: number }, nds: StudioNode[], excludeId?: string) => {
      const candidates = nds.filter((n) => {
        if (n.type !== 'boundary' || n.id === excludeId) return false
        const width = (n.style?.width as number) ?? 420
        const height = (n.style?.height as number) ?? 260
        return point.x >= n.position.x && point.x <= n.position.x + width && point.y >= n.position.y && point.y <= n.position.y + height
      })
      return candidates.sort((a, b) => {
        const areaOf = (n: StudioNode) => ((n.style?.width as number) ?? 420) * ((n.style?.height as number) ?? 260)
        return areaOf(a) - areaOf(b)
      })[0]
    },
    [],
  )

  const onNodeDragStop: OnNodeDrag<StudioNode> = useCallback(
    (_event, draggedNode) => {
      if (draggedNode.type === 'component') {
        setNodes((nds) => {
          const current = nds.find((n) => n.id === draggedNode.id)
          if (!current) return nds
          const abs = absolutePosition(current, nds)
          const target = boundaryAt(abs, nds, current.id)
          if ((target?.id ?? undefined) === current.parentId) return nds
          const newPosition = target ? { x: abs.x - target.position.x, y: abs.y - target.position.y } : abs
          return nds.map((n) =>
            n.id === current.id ? { ...n, position: newPosition, parentId: target?.id } : n,
          )
        })
        return
      }
      if (draggedNode.type === 'boundary') {
        // The reverse case: a component keeps whatever containment it had
        // when *it* was last dropped, since xyflow moves parented children
        // along with their parent automatically — nothing needs to react
        // when a boundary that already owns children is dragged. But a
        // boundary dragged so it now visually *encloses* components it
        // doesn't own (or that were dropped there before this boundary
        // existed/moved) never got checked at all: only a component's own
        // drag-stop used to run the containment test, so those components
        // stayed exactly as un-parented as before — just now sitting
        // inside a dashed box that implied otherwise. Re-running the same
        // containment test from the boundary's side catches that case.
        setNodes((nds) => {
          const boundary = nds.find((n) => n.id === draggedNode.id)
          if (!boundary) return nds
          let changed = false
          const next = nds.map((n) => {
            if (n.type !== 'component') return n
            const abs = absolutePosition(n, nds)
            const target = boundaryAt(abs, nds)
            if ((target?.id ?? undefined) === n.parentId) return n
            changed = true
            const newPosition = target ? { x: abs.x - target.position.x, y: abs.y - target.position.y } : abs
            return { ...n, position: newPosition, parentId: target?.id }
          })
          return changed ? next : nds
        })
      }
    },
    [setNodes, boundaryAt],
  )

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }, [])

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault()
      const kbId = event.dataTransfer.getData('application/hybridtm-kb-component')
      if (!kbId || !kb) return
      const kbComponent = kb.components[kbId]
      if (!kbComponent) return
      const position = screenToFlowPosition({ x: event.clientX, y: event.clientY })
      addComponentFromKb(kbId, kbComponent, position)
    },
    [kb, screenToFlowPosition, addComponentFromKb],
  )

  return (
    <div ref={wrapperRef} className="relative w-full h-full" onDragOver={onDragOver} onDrop={onDrop}>
      {nodes.filter((n) => n.type === 'component').length >= 2 && edges.length === 0 && (
        <div
          className="absolute bottom-4 left-1/2 -translate-x-1/2 z-10 px-3 py-1.5 rounded-full text-xs shadow"
          style={{ background: 'var(--surface-0)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
        >
          Drag from the ring on a block's right edge to another block's left-edge ring to connect them
        </div>
      )}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onSelectionChange={onSelectionChange}
        onNodeDragStop={onNodeDragStop}
        deleteKeyCode={['Backspace', 'Delete']}
        multiSelectionKeyCode={['Meta', 'Control']}
        // Otherwise selecting/dragging a boundary elevates it above its own
        // children (elevateNodesOnSelect, on by default) — see the zIndex
        // fields set alongside node construction in model.store.ts.
        zIndexMode="manual"
      >
        <Background />
        <Controls />
        <MiniMap pannable zoomable />
      </ReactFlow>
    </div>
  )
}

// Rendered inside a <ReactFlowProvider> that App.tsx owns — Toolbar needs
// useReactFlow() too (for PNG/SVG export, T-7.19), so the provider has to
// wrap both siblings rather than live inside this component alone.
export function FlowCanvas({ kb }: { kb: KbBundle | undefined }) {
  return <CanvasInner kb={kb} />
}
