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
      className="relative w-full h-full rounded-xl border-2 border-dashed"
      style={{
        borderColor: selected ? 'var(--accent)' : 'var(--border)',
        background: 'color-mix(in srgb, var(--surface-2) 40%, transparent)',
      }}
    >
      {/* `.react-flow__node-boundary` is click-through (tokens.css, so a
         component/edge underneath stays selectable) — pointer-events:none
         is inherited by descendants that don't set their own, and unlike
         the label right below, NodeResizer's own line/handle controls in
         this xyflow version don't set an explicit pointer-events at all,
         so they silently inherited 'none' too and stopped responding to
         drags. handleStyle/lineStyle inject inline pointer-events onto
         those exact elements to opt them back in, same idea as the label. */}
      <NodeResizer
        isVisible={selected}
        minWidth={MIN_BOUNDARY_WIDTH}
        minHeight={MIN_BOUNDARY_HEIGHT}
        color="var(--accent)"
        handleStyle={{ pointerEvents: 'all' }}
        lineStyle={{ pointerEvents: 'all' }}
        onResize={(_event, params) => resizeBoundary(id, params)}
      />
      {/* Sits just above the box rather than clipped inside its top-left
         corner (the old inline pill overlapped the border and got cut off
         by the canvas edge) — reads as a label for the region, not
         decoration painted on it.
         `.react-flow__node-boundary` is click-through (tokens.css) so a
         component or data-flow edge under this box stays selectable — that
         makes this label the one spot you can still click to select/drag
         the boundary itself, so it opts back in with pointerEvents: 'all'. */}
      <div
        className="absolute left-2 -top-6 px-1 text-xs font-medium whitespace-nowrap cursor-pointer"
        style={{ color: selected ? 'var(--accent)' : 'var(--text-secondary)', pointerEvents: 'all' }}
      >
        — {d.name}
      </div>
    </div>
  )
}
