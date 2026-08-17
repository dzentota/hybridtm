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

  const onNodeDragStop: OnNodeDrag<StudioNode> = useCallback(
    (_event, draggedNode) => {
      if (draggedNode.type !== 'component') return
      setNodes((nds) => {
        const current = nds.find((n) => n.id === draggedNode.id)
        if (!current) return nds
        const abs = absolutePosition(current, nds)
        const target = nds.find((n) => {
          if (n.type !== 'boundary' || n.id === current.id) return false
          const width = (n.style?.width as number) ?? 420
          const height = (n.style?.height as number) ?? 260
          return abs.x >= n.position.x && abs.x <= n.position.x + width && abs.y >= n.position.y && abs.y <= n.position.y + height
        })
        if ((target?.id ?? undefined) === current.parentId) return nds
        const newPosition = target ? { x: abs.x - target.position.x, y: abs.y - target.position.y } : abs
        return nds.map((n) =>
          n.id === current.id ? { ...n, position: newPosition, parentId: target?.id } : n,
        )
      })
    },
    [setNodes],
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
