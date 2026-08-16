import { BaseEdge, EdgeLabelRenderer, getBezierPath, type EdgeProps } from '@xyflow/react'
import type { DataFlowEdgeData, StudioEdge } from '../../store/model.store'

const severityColor: Record<string, string> = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  elevated: 'var(--severity-elevated)',
  medium: 'var(--severity-medium)',
  low: 'var(--severity-low)',
}

export function DataFlowEdge({
  id,
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
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const color = d.maxSeverity ? severityColor[d.maxSeverity] : 'var(--text-secondary)'

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: color,
          strokeWidth: selected ? 2.5 : 1.5,
          strokeDasharray: d.crossesBoundary ? '6 4' : undefined,
        }}
      />
      {d.protocol && (
        <EdgeLabelRenderer>
          <div
            className="text-[10px] px-1 rounded pointer-events-none"
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              background: 'var(--surface-0)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border)',
            }}
          >
            {d.protocol}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}
