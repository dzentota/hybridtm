import { NodeResizer, type NodeProps } from '@xyflow/react'
import { useModelStore, type BoundaryNodeData, type StudioNode } from '../../store/model.store'

const MIN_BOUNDARY_WIDTH = 240
const MIN_BOUNDARY_HEIGHT = 140

/** Grouping node for a trust boundary (T-7.5) — components dropped inside get
 * `parentId` set to this node's id by FlowCanvas's onNodeDragStop. Resizable
 * via NodeResizer when selected; resizing writes straight into the store
 * rather than relying on xyflow's own dimension-change plumbing, so the
 * result stays in the same `position`/`style.width/height` shape every
 * other boundary-reading code path (layout persistence, ELK, PNG export)
 * already expects. */
export function BoundaryNode({ id, data, selected }: NodeProps<StudioNode>) {
  const d = data as BoundaryNodeData
  const resizeBoundary = useModelStore((s) => s.resizeBoundary)

  return (
    <div
      className="w-full h-full rounded-xl border-2 border-dashed"
      style={{
        borderColor: selected ? 'var(--accent)' : 'var(--text-secondary)',
        background: 'color-mix(in srgb, var(--surface-2) 60%, transparent)',
      }}
    >
      <NodeResizer
        isVisible={selected}
        minWidth={MIN_BOUNDARY_WIDTH}
        minHeight={MIN_BOUNDARY_HEIGHT}
        color="var(--accent)"
        onResize={(_event, params) => resizeBoundary(id, params)}
      />
      <div
        className="px-2 py-1 text-xs font-medium rounded-tl-lg rounded-br-lg inline-block"
        style={{ background: 'var(--surface-2)', color: 'var(--text-secondary)' }}
      >
        {d.name} · {d.boundaryType}
      </div>
    </div>
  )
}
