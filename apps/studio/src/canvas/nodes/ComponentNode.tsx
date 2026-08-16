import { Handle, Position, type NodeProps } from '@xyflow/react'
import type { ComponentNodeData, StudioNode } from '../../store/model.store'

const severityGlyph: Record<string, string> = {
  critical: '⬢',
  high: '⬤',
  elevated: '◐',
  medium: '◯',
  low: '─',
}

export function ComponentNode({ data, selected }: NodeProps<StudioNode>) {
  const d = data as ComponentNodeData
  const propertyChips = Object.entries(d.properties)
    .filter(([, v]) => v === true || (typeof v === 'string' && v !== ''))
    .slice(0, 3)

  return (
    <div
      className="rounded-[10px] border bg-(--surface-0) shadow-[var(--shadow-node)] px-3 py-2 w-[220px] h-[96px] flex flex-col justify-between"
      style={{ borderColor: selected ? 'var(--accent)' : 'var(--border)', borderWidth: selected ? 2 : 1 }}
    >
      <Handle type="target" position={Position.Left} id="in" style={{ top: '50%' }} />
      <Handle type="source" position={Position.Right} id="out" style={{ top: '50%' }} />

      <div className="flex items-start justify-between gap-1">
        <div className="min-w-0">
          <div className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
            {d.name}
          </div>
          {d.kbName && (
            <div className="text-xs truncate" style={{ color: 'var(--text-secondary)' }}>
              {d.kbName} {d.kbVersion}
            </div>
          )}
        </div>
        {d.findingCount > 0 && d.maxSeverity && (
          <span className="severity-badge shrink-0" data-severity={d.maxSeverity}>
            {severityGlyph[d.maxSeverity]}
            {d.findingCount}
          </span>
        )}
      </div>

      {propertyChips.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {propertyChips.map(([key]) => (
            <span
              key={key}
              className="text-[10px] px-1.5 py-0.5 rounded-full"
              style={{ background: 'var(--surface-2)', color: 'var(--text-secondary)' }}
            >
              {key}
            </span>
          ))}
        </div>
      )}

      <div className="flex justify-between text-[10px]" style={{ color: 'var(--text-secondary)' }}>
        <span>◀ in</span>
        <span>out ▶</span>
      </div>
    </div>
  )
}
