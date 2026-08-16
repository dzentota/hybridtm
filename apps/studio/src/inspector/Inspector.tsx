import type { KbBundle } from '../api/types'
import { useModelStore } from '../store/model.store'
import { PropertyForm } from './PropertyForm'

/** Right-hand panel (T-7.9): shows the selected node's KB property schema
 * as an editable form, or a placeholder when nothing/a boundary is selected. */
export function Inspector({ kb }: { kb: KbBundle | undefined }) {
  const { nodes, selectedId, updateProperty } = useModelStore()
  const selected = nodes.find((n) => n.id === selectedId)

  if (!selected || selected.data.kind !== 'component') {
    return (
      <div className="p-4 text-sm" style={{ color: 'var(--text-secondary)' }}>
        Select a component to inspect its properties.
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
