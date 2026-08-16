import { Background, ReactFlow, ReactFlowProvider, type NodeProps } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { canonicalModelToGraph } from '../store/model.store'
import type { CanonicalModel } from '../api/types'
import type { ComponentNodeData, BoundaryNodeData, StudioNode } from '../store/model.store'

/** Read-only, store-independent node renderers for the diff view's two
 * preview canvases (T-7.22) — deliberately NOT the production
 * ComponentNode/DataFlowEdge, which read overlay mode and boundary
 * membership off the live editing session's global store. A snapshot of a
 * past model version has no business touching that store. */
function PreviewComponentNode({ data }: NodeProps<StudioNode>) {
  const d = data as ComponentNodeData
  return (
    <div
      className="rounded-lg border px-2 py-1.5 text-xs w-[140px]"
      style={{ borderColor: 'var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }}
    >
      <div className="font-medium truncate">{d.name}</div>
    </div>
  )
}

function PreviewBoundaryNode({ data }: NodeProps<StudioNode>) {
  const d = data as BoundaryNodeData
  return (
    <div
      className="w-full h-full rounded-lg border-2 border-dashed"
      style={{ borderColor: 'var(--text-secondary)', background: 'color-mix(in srgb, var(--surface-2) 50%, transparent)' }}
    >
      <div className="text-[10px] px-1" style={{ color: 'var(--text-secondary)' }}>
        {d.name}
      </div>
    </div>
  )
}

const nodeTypes = { component: PreviewComponentNode, boundary: PreviewBoundaryNode }

export function PreviewCanvas({ model, label }: { model: CanonicalModel | undefined; label: string }) {
  const { nodes, edges } = model ? canonicalModelToGraph(model) : { nodes: [], edges: [] }

  return (
    <div className="flex flex-col h-full min-h-0" style={{ border: '1px solid var(--border)' }}>
      <div className="px-2 py-1 text-xs font-medium" style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
        {label}
      </div>
      <div className="flex-1 min-h-0">
        <ReactFlowProvider>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            panOnDrag
            zoomOnScroll
          >
            <Background />
          </ReactFlow>
        </ReactFlowProvider>
      </div>
    </div>
  )
}
