import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { KbBundle } from '../api/types'
import { useModelStore } from '../store/model.store'
import { PropertyForm } from './PropertyForm'
import { DataFlowAssets } from './DataFlowAssets'
import { PROTOCOLS, BOUNDARY_TYPES } from '../canvas/domainEnums'

const selectStyle = { border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }
const inputStyle = { border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }

/** Free-text tags as one comma-separated field — committed on blur/Enter
 * rather than on every keystroke, so typing "pci, " doesn't briefly produce
 * a spurious empty tag mid-edit. */
function TagsField({ tags, onChange }: { tags: string[]; onChange: (tags: string[]) => void }) {
  const [draft, setDraft] = useState(tags.join(', '))
  const commit = () => {
    const parsed = draft
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean)
    onChange(parsed)
    setDraft(parsed.join(', '))
  }
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span style={{ color: 'var(--text-secondary)' }}>Tags</span>
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault()
            commit()
          }
        }}
        placeholder="e.g. pci, external-facing"
        aria-label="Tags"
        className="px-2 py-1.5 rounded"
        style={inputStyle}
      />
    </label>
  )
}

/** Right-hand panel (T-7.9): shows the selected component's KB property
 * schema, the selected trust boundary's name/type, or the selected data
 * flow's protocol — whichever is currently selected on the canvas — or a
 * placeholder when nothing is selected. */
export function Inspector({ kb }: { kb: KbBundle | undefined }) {
  const { t } = useTranslation()
  const { nodes, edges, selectedId, selectedEdgeId, updateProperty, updateBoundary, updateEdgeProtocol, updateEdgeData } =
    useModelStore()
  const selected = nodes.find((n) => n.id === selectedId)
  const selectedEdge = edges.find((e) => e.id === selectedEdgeId)

  if (selectedEdge) {
    const sourceName = nodes.find((n) => n.id === selectedEdge.source)?.data.name ?? selectedEdge.source
    const targetName = nodes.find((n) => n.id === selectedEdge.target)?.data.name ?? selectedEdge.target
    return (
      <div className="p-4 overflow-y-auto h-full flex flex-col gap-4">
        <div>
          <div className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
            Data flow
          </div>
          <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            {sourceName} → {targetName}
          </div>
        </div>
        <label className="flex flex-col gap-1 text-sm">
          <span style={{ color: 'var(--text-secondary)' }}>Protocol</span>
          <select
            aria-label="Data flow protocol"
            value={selectedEdge.data?.protocol ?? 'unknown-protocol'}
            onChange={(e) => updateEdgeProtocol(selectedEdge.id, e.target.value)}
            className="px-2 py-1.5 rounded"
            style={selectStyle}
          >
            {PROTOCOLS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label} {p.encrypted ? '🔒' : ''}
              </option>
            ))}
          </select>
          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            Rules flag unencrypted transit for sensitive data — "Unknown" is treated as unencrypted.
          </span>
        </label>

        <DataFlowAssets
          edgeId={selectedEdge.id}
          dataSent={selectedEdge.data?.dataSent ?? []}
          dataReceived={selectedEdge.data?.dataReceived ?? []}
        />

        <TagsField
          key={selectedEdge.id}
          tags={selectedEdge.data?.tags ?? []}
          onChange={(tags) => updateEdgeData(selectedEdge.id, { tags })}
        />
      </div>
    )
  }

  if (selected && selected.data.kind === 'boundary') {
    const contained = nodes.filter((n) => n.parentId === selected.id)
    return (
      <div className="p-4 overflow-y-auto h-full flex flex-col gap-3">
        <div className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
          Trust boundary
        </div>
        <label className="flex flex-col gap-1 text-sm">
          <span style={{ color: 'var(--text-secondary)' }}>Name</span>
          <input
            value={selected.data.name}
            onChange={(e) => updateBoundary(selected.id, { name: e.target.value })}
            className="px-2 py-1.5 rounded"
            style={inputStyle}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span style={{ color: 'var(--text-secondary)' }}>Type</span>
          <select
            aria-label="Trust boundary type"
            value={selected.data.boundaryType}
            onChange={(e) => updateBoundary(selected.id, { boundaryType: e.target.value })}
            className="px-2 py-1.5 rounded"
            style={selectStyle}
          >
            {BOUNDARY_TYPES.map((b) => (
              <option key={b.value} value={b.value}>
                {b.label}
              </option>
            ))}
          </select>
        </label>
        <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {contained.length === 0
            ? 'No components inside — drag a component onto this box on the canvas to place it in the boundary.'
            : `Contains: ${contained.map((n) => n.data.name).join(', ')}`}
        </div>
      </div>
    )
  }

  if (!selected || selected.data.kind !== 'component') {
    return (
      <div className="p-4 text-sm" style={{ color: 'var(--text-secondary)' }}>
        {t('inspector.empty')}
      </div>
    )
  }

  const kbComponent = selected.data.kbComponentId ? kb?.components[selected.data.kbComponentId] : undefined

  return (
    <div className="p-4 overflow-y-auto h-full">
      <div className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
        {selected.data.name}
      </div>
      <div className="text-xs mb-4" style={{ color: 'var(--text-secondary)' }}>
        {selected.data.traits.join(', ') || 'no traits'}
      </div>

      {kbComponent ? (
        <PropertyForm
          properties={kbComponent.properties}
          values={selected.data.properties}
          onChange={(propId, value) => updateProperty(selected.id, propId, value)}
        />
      ) : (
        <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          No knowledge-base component linked — this node analyzes with fewer rules.
        </div>
      )}
    </div>
  )
}
