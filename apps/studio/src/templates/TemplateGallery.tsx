import { useReactFlow } from '@xyflow/react'
import { useModelStore } from '../store/model.store'
import { STARTER_TEMPLATES } from './starterTemplates'
import type { KbBundle } from '../api/types'

/** T-7.16's template gallery. Six starter architectures (see
 * starterTemplates.ts for why these are client-seeded rather than KB
 * `kind: Template` entities) inserted as one atomic undo step via
 * insertTemplate — the KB lookup happens here so a template whose
 * components got renamed degrades to "unavailable" instead of crashing. */
export function TemplateGallery({
  kb,
  open,
  onClose,
}: {
  kb: KbBundle | undefined
  open: boolean
  onClose: () => void
}) {
  const insertTemplate = useModelStore((s) => s.insertTemplate)
  const { screenToFlowPosition } = useReactFlow()

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'color-mix(in srgb, black 30%, transparent)' }}
      role="presentation"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Architecture templates"
        className="w-[640px] max-h-[70vh] rounded-lg shadow-xl overflow-hidden flex flex-col"
        style={{ background: 'var(--surface-0)', border: '1px solid var(--border)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-3 py-2 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            Architecture templates
          </span>
          <button onClick={onClose} aria-label="Close templates" className="text-sm px-2 py-1 rounded" style={{ border: '1px solid var(--border)' }}>
            ✕
          </button>
        </div>
        <div className="grid grid-cols-2 gap-3 p-3 overflow-y-auto">
          {STARTER_TEMPLATES.map((template) => {
            const missing = kb ? template.components.filter((c) => !kb.components[c.kbId]) : template.components
            const available = !!kb && missing.length === 0

            return (
              <div
                key={template.id}
                className="p-3 rounded-lg flex flex-col gap-2"
                style={{ border: '1px solid var(--border)', background: 'var(--surface-1)' }}
              >
                <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                  {template.name}
                </div>
                <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                  {template.description}
                </div>
                <div className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                  {template.components.length} components · {template.edges.length} flows
                </div>
                <button
                  type="button"
                  disabled={!available}
                  className="mt-1 text-sm font-medium px-2 py-1 rounded disabled:opacity-40"
                  style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
                  onClick={() => {
                    if (!kb) return
                    const center = screenToFlowPosition({ x: window.innerWidth / 2, y: window.innerHeight / 2 })
                    const items = template.components.map((c) => ({
                      kbId: c.kbId,
                      kb: kb.components[c.kbId],
                      position: { x: center.x + c.x, y: center.y + c.y },
                    }))
                    insertTemplate(items, template.edges)
                    onClose()
                  }}
                >
                  {available ? 'Insert' : `Unavailable (${missing.length} component${missing.length === 1 ? '' : 's'} missing)`}
                </button>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
