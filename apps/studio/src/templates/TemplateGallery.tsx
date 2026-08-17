import { useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useModelStore } from '../store/model.store'
import { STARTER_TEMPLATES } from './starterTemplates'
import { createModelTemplate, deleteModelTemplate, listModelTemplates } from '../api/client'
import type { KbBundle } from '../api/types'

/** T-7.16's template gallery. Six starter architectures (see
 * starterTemplates.ts for why these are client-seeded rather than KB
 * `kind: Template` entities) inserted as one atomic undo step via
 * insertTemplate — the KB lookup happens here so a template whose
 * components got renamed degrades to "unavailable" instead of crashing.
 * Also hosts user-saved templates (a full canonical model + layout the
 * user chose to keep for reuse, distinct from both the starter list above
 * and the KB's own `Kind::Template` entries — see ModelTemplate.php). */
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
  const insertCanonicalModel = useModelStore((s) => s.insertCanonicalModel)
  const toCanonicalModel = useModelStore((s) => s.toCanonicalModel)
  const toLayout = useModelStore((s) => s.toLayout)
  const { screenToFlowPosition } = useReactFlow()
  const queryClient = useQueryClient()
  const [saving, setSaving] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  const savedTemplates = useQuery({ queryKey: ['model-templates'], queryFn: listModelTemplates, enabled: open })

  const saveMutation = useMutation({
    mutationFn: () => createModelTemplate(name.trim(), description.trim(), toCanonicalModel(), toLayout()),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['model-templates'] })
      setName('')
      setDescription('')
      setSaving(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteModelTemplate(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['model-templates'] }),
  })

  const anchor = () => screenToFlowPosition({ x: window.innerWidth / 2, y: window.innerHeight / 2 })

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
        className="w-[680px] max-h-[80vh] rounded-lg shadow-xl overflow-hidden flex flex-col"
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

        <div className="overflow-y-auto">
          <div className="p-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>
                Your templates
              </span>
              <button
                type="button"
                aria-label="Save current model as template"
                onClick={() => setSaving((v) => !v)}
                className="text-xs px-2 py-1 rounded"
                style={{ border: '1px solid var(--border)' }}
              >
                + Save current model
              </button>
            </div>

            {saving && (
              <form
                className="flex flex-col gap-1.5 p-2 mb-2 rounded"
                style={{ background: 'var(--surface-1)' }}
                onSubmit={(e) => {
                  e.preventDefault()
                  if (name.trim()) saveMutation.mutate()
                }}
              >
                <input
                  autoFocus
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Template name"
                  aria-label="Template name"
                  className="px-2 py-1 rounded text-sm"
                  style={{ border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }}
                />
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Description (optional)"
                  aria-label="Template description"
                  className="px-2 py-1 rounded text-sm"
                  style={{ border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }}
                />
                <div className="flex gap-1.5">
                  <button
                    type="submit"
                    disabled={!name.trim() || saveMutation.isPending}
                    className="text-xs px-2 py-1 rounded font-medium disabled:opacity-40"
                    style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
                  >
                    {saveMutation.isPending ? 'Saving…' : 'Save'}
                  </button>
                  <button type="button" onClick={() => setSaving(false)} className="text-xs px-2 py-1 rounded" style={{ border: '1px solid var(--border)' }}>
                    Cancel
                  </button>
                </div>
              </form>
            )}

            {savedTemplates.data?.length ? (
              <div className="grid grid-cols-2 gap-2">
                {savedTemplates.data.map((tpl) => (
                  <div key={tpl.id} className="p-2 rounded flex flex-col gap-1" style={{ border: '1px solid var(--border)' }}>
                    <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                      {tpl.name}
                    </div>
                    {tpl.description && (
                      <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                        {tpl.description}
                      </div>
                    )}
                    <div className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                      {tpl.data.components.length} components · {tpl.data.dataFlows.length} flows
                    </div>
                    <div className="flex gap-1.5 mt-1">
                      <button
                        type="button"
                        onClick={() => {
                          insertCanonicalModel(tpl.data, tpl.layout ?? undefined, anchor())
                          onClose()
                        }}
                        className="text-xs px-2 py-1 rounded font-medium flex-1"
                        style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
                      >
                        Insert
                      </button>
                      <button
                        type="button"
                        aria-label={`Delete ${tpl.name}`}
                        onClick={() => deleteMutation.mutate(tpl.id)}
                        className="text-xs px-2 py-1 rounded"
                        style={{ border: '1px solid var(--border)' }}
                      >
                        ✕
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                No saved templates yet — build something on the canvas and click "Save current model".
              </div>
            )}
          </div>

          <div className="p-3">
            <div className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-secondary)' }}>
              Starter architectures
            </div>
            <div className="grid grid-cols-2 gap-3">
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
                        const center = anchor()
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
      </div>
    </div>
  )
}
