import type { NodeProps } from '@xyflow/react'
import type { BoundaryNodeData, StudioNode } from '../../store/model.store'

/** Grouping node for a trust boundary (T-7.5) — components dropped inside get
 * `parentId` set to this node's id by FlowCanvas's onNodeDragStop. */
export function BoundaryNode({ data, selected }: NodeProps<StudioNode>) {
  const d = data as BoundaryNodeData

  return (
    <div
      className="w-full h-full rounded-xl border-2 border-dashed"
      style={{
        borderColor: selected ? 'var(--accent)' : 'var(--text-secondary)',
        background: 'color-mix(in srgb, var(--surface-2) 60%, transparent)',
      }}
    >
      <div
        className="px-2 py-1 text-xs font-medium rounded-tl-lg rounded-br-lg inline-block"
        style={{ background: 'var(--surface-2)', color: 'var(--text-secondary)' }}
      >
        {d.name} · {d.boundaryType}
      </div>
    </div>
  )
}
