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
  useReactFlow,
  ReactFlowProvider,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useModelStore, type StudioNode } from '../store/model.store'
import { ComponentNode } from './nodes/ComponentNode'
import { BoundaryNode } from './nodes/BoundaryNode'
import { DataFlowEdge } from './edges/DataFlowEdge'
import type { KbBundle } from '../api/types'

const nodeTypes = { component: ComponentNode, boundary: BoundaryNode }
const edgeTypes = { dataflow: DataFlowEdge }

function CanvasInner({ kb }: { kb: KbBundle | undefined }) {
  const { nodes, edges, setNodes, setEdges, select, addComponentFromKb } = useModelStore()
  const wrapperRef = useRef<HTMLDivElement>(null)
  const { screenToFlowPosition } = useReactFlow()

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => setNodes((nds) => applyNodeChanges(changes, nds) as typeof nds),
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
    ({ nodes: sel }: { nodes: StudioNode[] }) => select(sel[0]?.id ?? null),
    [select],
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
    <div ref={wrapperRef} className="w-full h-full" onDragOver={onDragOver} onDrop={onDrop}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onSelectionChange={onSelectionChange}
        deleteKeyCode={['Backspace', 'Delete']}
        multiSelectionKeyCode={['Meta', 'Control']}
        fitView
      >
        <Background />
        <Controls />
        <MiniMap pannable zoomable />
      </ReactFlow>
    </div>
  )
}

export function FlowCanvas({ kb }: { kb: KbBundle | undefined }) {
  return (
    <ReactFlowProvider>
      <CanvasInner kb={kb} />
    </ReactFlowProvider>
  )
}
