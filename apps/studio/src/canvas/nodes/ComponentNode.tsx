import { Handle, NodeToolbar, Position, type NodeProps } from '@xyflow/react'
import { useModelStore, type ComponentNodeData, type StudioNode } from '../../store/model.store'
import { ComponentIcon } from '../../design/ComponentIcon'
import { IconButton } from '../../design/IconButton'

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

export function ComponentNode({ id, data, selected, parentId }: NodeProps<StudioNode>) {
  const d = data as ComponentNodeData
  const overlayMode = useModelStore((s) => s.overlayMode)
  const setFocusSubject = useModelStore((s) => s.setFocusSubject)
  const duplicateNode = useModelStore((s) => s.duplicateNode)
  const removeNode = useModelStore((s) => s.removeNode)
  const selectedStoryId = useModelStore((s) => s.selectedStoryId)
  const abuseCases = useModelStore((s) => s.abuseCases)
  const storyHighlighted = Boolean(
    selectedStoryId &&
      abuseCases.some(
        (c) =>
          c.title === selectedStoryId &&
          ((c.assetIds ?? []).includes(id) || c.actorId === id),
      ),
  )

  const highlight =
    overlayMode === 'exposure'
      ? !parentId
        ? { color: 'var(--severity-high)', label: 'not in any trust boundary' }
        : null
      : overlayHighlight(overlayMode, d)

  const borderColor = selected
    ? 'var(--accent)'
    : storyHighlighted
      ? 'var(--accent)'
      : highlight
        ? highlight.color
        : 'var(--border)'

  return (
    <div
      className="rounded-[10px] border bg-(--surface-0) shadow-[var(--shadow-node)] px-3 py-2 w-[220px] h-[76px] flex flex-col justify-between"
      style={{
        borderColor,
        borderWidth: selected || storyHighlighted || highlight ? 2 : 1,
        boxShadow: storyHighlighted ? '0 0 0 2px color-mix(in srgb, var(--accent) 35%, transparent)' : undefined,
      }}
      title={storyHighlighted ? `Linked to abuser story ${selectedStoryId}` : highlight?.label}
    >
      {/* Floating action bar, only while selected — keeps the node face
         itself down to icon + name + severity so the diagram reads as an
         architecture, not a property dump; per-node detail lives here and
         in the Inspector instead of as chips on every block. */}
      <NodeToolbar isVisible={selected} position={Position.Top} offset={8}>
        <div
          className="flex items-center gap-0.5 p-0.5 rounded-lg shadow-lg"
          style={{ background: 'var(--surface-0)', border: '1px solid var(--border)' }}
        >
          <IconButton
            icon="mdi:shield-alert-outline"
            label={d.findingCount > 0 ? `View ${d.findingCount} finding(s) for ${d.name}` : 'No findings yet for this component'}
            disabled={d.findingCount === 0}
            onClick={() => setFocusSubject(id)}
          />
          <IconButton icon="mdi:content-copy" label={`Duplicate ${d.name}`} onClick={() => duplicateNode(id)} />
          <IconButton icon="mdi:trash-can-outline" label={`Delete ${d.name}`} variant="danger" onClick={() => removeNode(id)} />
        </div>
      </NodeToolbar>

      <Handle
        type="target"
        position={Position.Left}
        id="in"
        title="Drag a connection here to route data into this block"
        className="hybridtm-handle"
        style={{ top: '50%' }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="out"
        title="Drag from here to another block to connect them"
        className="hybridtm-handle"
        style={{ top: '50%' }}
      />

      <div className="flex items-start justify-between gap-1">
        <div className="flex items-start gap-1.5 min-w-0">
          <ComponentIcon icon={d.icon} color={d.color} size={14} />
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
        </div>
        {d.findingCount > 0 && d.maxSeverity && (
          <span className="severity-badge shrink-0" data-severity={d.maxSeverity}>
            {severityGlyph[d.maxSeverity]}
            {d.findingCount}
          </span>
        )}
      </div>

      <div className="flex justify-between text-[10px]" style={{ color: 'var(--text-secondary)' }}>
        <span>◀ in</span>
        <span>out ▶</span>
      </div>
    </div>
  )
}
