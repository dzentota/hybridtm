import { useMemo, useState } from 'react'
import type { KbBundle } from '../api/types'

/** Category tree + search over the KB bundle (T-7.8). Drag a row onto the
 * canvas to place it; FlowCanvas reads the id back off the drag event. */
export function ComponentPalette({ kb }: { kb: KbBundle | undefined }) {
  const [query, setQuery] = useState('')

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
    <div className="flex flex-col h-full" style={{ background: 'var(--surface-1)', borderRight: '1px solid var(--border)' }}>
      <div className="p-2">
        <input
          id="component-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search components…"
          className="w-full text-sm px-2 py-1.5 rounded border"
          style={{ background: 'var(--surface-0)', borderColor: 'var(--border)', color: 'var(--text-primary)' }}
        />
      </div>
      <div className="flex-1 overflow-y-auto px-2 pb-2">
        {!kb && <div className="text-xs p-2" style={{ color: 'var(--text-secondary)' }}>Loading knowledge base…</div>}
        {[...grouped.entries()].map(([category, items]) => (
          <div key={category} className="mb-3">
            <div className="text-xs font-semibold uppercase tracking-wide px-1 mb-1" style={{ color: 'var(--text-secondary)' }}>
              {category}
            </div>
            {items.map(([id, component]) => (
              <div
                key={id}
                draggable
                onDragStart={(e) => {
                  e.dataTransfer.setData('application/hybridtm-kb-component', id)
                  e.dataTransfer.effectAllowed = 'move'
                }}
                className="flex items-center justify-between text-sm px-2 py-1.5 rounded cursor-grab hover:bg-(--surface-2)"
                style={{ color: 'var(--text-primary)' }}
              >
                <span>{component.metadata.name}</span>
                <span className="text-[10px] px-1.5 rounded-full" style={{ background: 'var(--surface-2)', color: 'var(--text-secondary)' }}>
                  {component.rules.length} rules
                </span>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}
