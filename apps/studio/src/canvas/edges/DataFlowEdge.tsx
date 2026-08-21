import { BaseEdge, EdgeLabelRenderer, getBezierPath, type EdgeProps } from '@xyflow/react'
import { useModelStore, type DataFlowEdgeData, type StudioEdge } from '../../store/model.store'

const severityColor: Record<string, string> = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  elevated: 'var(--severity-elevated)',
  medium: 'var(--severity-medium)',
  low: 'var(--severity-low)',
}

export function DataFlowEdge({
  id,
  source,
  target,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
}: EdgeProps<StudioEdge>) {
  const d = data as DataFlowEdgeData
  const overlayMode = useModelStore((s) => s.overlayMode)
  // Computed live off current node parentage rather than trusting a stale
  // `data.crossesBoundary` flag — nothing ever wrote that field (T-7.6's
  // "edges crossing a boundary look different" claim had no data behind it
  // until this fix).
  const crossesBoundary = useModelStore((s) => {
    const sourceNode = s.nodes.find((n) => n.id === source)
    const targetNode = s.nodes.find((n) => n.id === target)
    return (sourceNode?.parentId ?? null) !== (targetNode?.parentId ?? null)
  })
  const storyHighlighted = useModelStore((s) => {
    if (!s.selectedStoryId) return false
    const story = s.abuseCases.find((c) => c.title === s.selectedStoryId)
    return Boolean(story?.dataFlowIds?.includes(id))
  })
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const color =
    storyHighlighted
      ? 'var(--accent)'
      : overlayMode === 'exposure' && crossesBoundary
        ? 'var(--severity-high)'
        : d.maxSeverity
          ? severityColor[d.maxSeverity]
          : 'var(--text-secondary)'

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: color,
          strokeWidth: selected || storyHighlighted ? 2.5 : 1.5,
          strokeDasharray: crossesBoundary ? '6 4' : undefined,
        }}
      />
      {(d.protocol || d.tags?.length || d.dataSent?.length || d.dataReceived?.length) && (
        <EdgeLabelRenderer>
          <div
            className="flex flex-col items-center gap-0.5 pointer-events-none"
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            }}
          >
            {d.protocol && (
              <div
                className="text-[10px] px-1 rounded"
                style={{ background: 'var(--surface-0)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}
              >
                {d.protocol}
              </div>
            )}
            {(d.dataSent?.length || d.dataReceived?.length || d.tags?.length) ? (
              <div
                className="text-[9px] px-1 rounded-full"
                style={{ background: 'var(--surface-2)', color: 'var(--text-secondary)' }}
                title={d.tags?.join(', ')}
              >
                {d.dataSent?.length ? `→${d.dataSent.length}` : ''}
                {d.dataReceived?.length ? ` ←${d.dataReceived.length}` : ''}
                {d.tags?.length ? ` 🏷️${d.tags.length}` : ''}
              </div>
            ) : null}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}
