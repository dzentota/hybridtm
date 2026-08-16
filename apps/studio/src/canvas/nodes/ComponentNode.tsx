import { Handle, Position, type NodeProps } from '@xyflow/react'
import { useModelStore, type ComponentNodeData, type StudioNode } from '../../store/model.store'

const severityGlyph: Record<string, string> = {
  critical: '⬢',
  high: '⬤',
  elevated: '◐',
  medium: '◯',
  low: '─',
}

const DATA_TRAIT_HINTS = ['datastore', 'data', 'pii', 'cache', 'storage', 'secrets']

/** Overlay modes (T-7.17) restyle nodes from data already on hand — no
 * extra KB lookups, so switching modes never touches the graph layout.
 * 'data'/'coverage' are necessarily approximations of what a full
 * server-computed overlay would show: 'data' flags components whose
 * declared traits merely *suggest* they handle data, and 'coverage' flags
 * components with no traits at all as a proxy for "nothing rules can key
 * off of yet" — both disclosed simplifications, not real KB queries. */
function overlayHighlight(mode: string, d: ComponentNodeData): { color: string; label: string } | null {
  if (mode === 'data') {
    const isDataish = d.traits.some((t) => DATA_TRAIT_HINTS.some((hint) => t.includes(hint)))
    return isDataish ? { color: 'var(--accent)', label: 'handles data' } : null
  }
  if (mode === 'coverage') {
    return d.traits.length === 0 ? { color: 'var(--severity-medium)', label: 'no traits declared' } : null
  }
  return null
}

export function ComponentNode({ data, selected, parentId }: NodeProps<StudioNode>) {
  const d = data as ComponentNodeData
  const overlayMode = useModelStore((s) => s.overlayMode)
  const propertyChips = Object.entries(d.properties)
    .filter(([, v]) => v === true || (typeof v === 'string' && v !== ''))
    .slice(0, 3)

  const highlight =
    overlayMode === 'exposure'
      ? !parentId
        ? { color: 'var(--severity-high)', label: 'not in any trust boundary' }
        : null
      : overlayHighlight(overlayMode, d)

  return (
    <div
      className="rounded-[10px] border bg-(--surface-0) shadow-[var(--shadow-node)] px-3 py-2 w-[220px] h-[96px] flex flex-col justify-between"
      style={{
        borderColor: selected ? 'var(--accent)' : highlight ? highlight.color : 'var(--border)',
        borderWidth: selected || highlight ? 2 : 1,
      }}
      title={highlight?.label}
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
