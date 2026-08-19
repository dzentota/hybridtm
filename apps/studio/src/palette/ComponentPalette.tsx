import { useMemo, useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import { useTranslation } from 'react-i18next'
import { cascadeOffset, useModelStore } from '../store/model.store'
import { ComponentIcon } from '../design/ComponentIcon'
import type { KbBundle } from '../api/types'

/** Category tree + search over the KB bundle (T-7.8). Drag a row onto the
 * canvas to place it, or focus a row with Tab and press Enter/Space — drag
 * handles alone aren't operable without a pointer (T-7.20). FlowCanvas
 * reads the id back off the drag event for the drag path; the keyboard
 * path calls the same store action directly. */
export function ComponentPalette({ kb, onCollapse }: { kb: KbBundle | undefined; onCollapse: () => void }) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const addComponentFromKb = useModelStore((s) => s.addComponentFromKb)
  const { screenToFlowPosition } = useReactFlow()

  const grouped = useMemo(() => {
    if (!kb) return new Map<string, [string, KbBundle['components'][string]][]>()
    const q = query.trim().toLowerCase()
    const entries = Object.entries(kb.components).filter(([id, c]) =>
      q === '' || id.includes(q) || c.metadata.name.toLowerCase().includes(q),
    )
    const byCategory = new Map<string, [string, KbBundle['components'][string]][]>()
    for (const entry of entries) {
      const categories = entry[1].metadata.categories ?? ['uncategorized']
      for (const cat of categories) {
        const list = byCategory.get(cat) ?? []
        list.push(entry)
        byCategory.set(cat, list)
      }
    }
    return byCategory
  }, [kb, query])

  return (
    <div className="relative flex flex-col h-full min-h-0" style={{ background: 'var(--surface-1)', borderRight: '1px solid var(--border)' }}>
      <button
        type="button"
        aria-label="Collapse component palette"
        title="Collapse panel"
        onClick={onCollapse}
        className="absolute -right-3 top-1/2 -translate-y-1/2 z-10 w-6 h-10 rounded flex items-center justify-center text-sm"
        style={{ background: 'var(--surface-0)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
      >
        ‹
      </button>
      <div className="p-2 shrink-0">
        <input
          id="component-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('palette.search')}
          className="w-full text-sm px-2 py-1.5 rounded border"
          style={{ background: 'var(--surface-0)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
        />
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto px-2 pb-2">
        {!kb && <div className="text-xs p-2" style={{ color: 'var(--text-secondary)' }}>{t('palette.loading')}</div>}
        {[...grouped.entries()].map(([category, items]) => (
          <div key={category} className="mb-4">
            <div className="text-[11px] font-semibold uppercase tracking-wider px-2 mb-1.5" style={{ color: 'var(--text-secondary)' }}>
              {category}
            </div>
            {items.map(([id, component]) => (
              <div
                key={id}
                draggable
                role="button"
                tabIndex={0}
                aria-label={t('palette.addAria', { name: component.metadata.name })}
                title={t('palette.rules', { count: component.rules.length })}
                onDragStart={(e) => {
                  e.dataTransfer.setData('application/hybridtm-kb-component', id)
                  e.dataTransfer.effectAllowed = 'move'
                }}
                onKeyDown={(e) => {
                  if (e.key !== 'Enter' && e.key !== ' ') return
                  e.preventDefault()
                  const center = screenToFlowPosition({ x: window.innerWidth / 2, y: window.innerHeight / 2 })
                  const offset = cascadeOffset(useModelStore.getState().nodes.length)
                  addComponentFromKb(id, component, { x: center.x + offset.x, y: center.y + offset.y })
                }}
                className="flex items-center gap-2.5 text-sm px-2 py-2 rounded-lg cursor-grab hover:bg-(--surface-2) focus-visible:outline focus-visible:outline-2"
                style={{ color: 'var(--text-primary)', outlineColor: 'var(--accent)' }}
              >
                <ComponentIcon icon={component.metadata.icon} color={component.metadata.color} size={17} />
                <span className="truncate">{component.metadata.name}</span>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}
