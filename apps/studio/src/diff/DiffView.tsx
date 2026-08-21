import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { analyze, listModelVersions, type ModelVersionSummary } from '../api/client'
import { computeModelDiff, computeRiskDelta } from './computeDiff'
import { PreviewCanvas } from './PreviewCanvas'

const STATUS_LABEL: Record<string, string> = { added: '+ added', removed: '− removed', changed: '~ changed' }
const STATUS_COLOR: Record<string, string> = {
  added: 'var(--severity-low)',
  removed: 'var(--severity-critical)',
  changed: 'var(--severity-medium)',
}

const SEVERITIES = ['critical', 'high', 'elevated', 'medium', 'low']

function VersionPicker({
  versions,
  value,
  onChange,
  label,
}: {
  versions: ModelVersionSummary[]
  value: string
  onChange: (id: string) => void
  label: string
}) {
  return (
    <label className="flex items-center gap-1.5 text-sm">
      <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-1.5 py-1 rounded text-sm"
        style={{ border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }}
      >
        {versions.map((v, i) => (
          <option key={v.id} value={v.id}>
            {v.data.model.title} — v{versions.length - i} ({v.id.slice(0, 8)})
          </option>
        ))}
      </select>
    </label>
  )
}

/** Version diff (T-7.22): two read-only preview canvases + a structural
 * change list + a risk delta table. Model versions have no `project`
 * ApiFilter server-side, so this fetches the whole visible collection and
 * lets the user pick any two — fine for the single-project dev flow this
 * app currently supports. */
export function DiffView({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { data: versions } = useQuery({
    queryKey: ['model-versions'],
    queryFn: listModelVersions,
    enabled: open,
  })
  const [fromId, setFromId] = useState('')
  const [toId, setToId] = useState('')

  useEffect(() => {
    if (!versions || versions.length === 0) return
    if (!fromId) setFromId(versions[Math.min(1, versions.length - 1)].id)
    if (!toId) setToId(versions[0].id)
  }, [versions, fromId, toId])

  const fromVersion = versions?.find((v) => v.id === fromId)
  const toVersion = versions?.find((v) => v.id === toId)

  const diff = useMemo(() => {
    if (!fromVersion || !toVersion) return null
    return computeModelDiff(fromVersion.data, toVersion.data)
  }, [fromVersion, toVersion])

  const {
    data: riskDelta,
    isError: riskDeltaError,
    isLoading: riskDeltaLoading,
  } = useQuery({
    queryKey: ['diff-risk-delta', fromId, toId],
    queryFn: async () => {
      const [beforeResult, afterResult] = await Promise.all([analyze(fromId), analyze(toId)])
      return computeRiskDelta(beforeResult.findings, afterResult.findings)
    },
    enabled: open && !!fromId && !!toId && fromId !== toId,
    retry: false,
  })

  if (!open) return null

  const changeCount = diff ? diff.components.length + diff.trustBoundaries.length + diff.dataFlows.length : 0

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
        aria-label="Compare model versions"
        className="w-[960px] h-[80vh] rounded-lg shadow-xl overflow-hidden flex flex-col"
        style={{ background: 'var(--surface-0)', border: '1px solid var(--border)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-3 py-2 flex items-center gap-3" style={{ borderBottom: '1px solid var(--border)' }}>
          <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            Compare versions
          </span>
          {versions && versions.length >= 2 && (
            <>
              <VersionPicker versions={versions} value={fromId} onChange={setFromId} label="From" />
              <VersionPicker versions={versions} value={toId} onChange={setToId} label="To" />
            </>
          )}
          <button onClick={onClose} aria-label="Close version comparison" className="ml-auto text-sm px-2 py-1 rounded" style={{ border: '1px solid var(--border)' }}>
            ✕
          </button>
        </div>

        {versions && versions.length < 2 && (
          <div className="p-4 text-sm" style={{ color: 'var(--text-secondary)' }}>
            Need at least two saved model versions to compare — run analysis once more after making a change.
          </div>
        )}

        {versions && versions.length >= 2 && (
          <div className="flex-1 min-h-0 flex flex-col">
            <div className="flex-1 min-h-0 grid grid-cols-2 gap-2 p-2">
              <PreviewCanvas model={fromVersion?.data} layout={fromVersion?.layout} label="From" />
              <PreviewCanvas model={toVersion?.data} layout={toVersion?.layout} label="To" />
            </div>
            <div className="flex-1 min-h-0 overflow-y-auto p-3" style={{ borderTop: '1px solid var(--border)' }}>
              {riskDeltaLoading && (
                <div className="text-xs mb-2" style={{ color: 'var(--text-secondary)' }}>
                  Computing risk delta…
                </div>
              )}
              {riskDeltaError && (
                <div className="text-xs mb-2" style={{ color: 'var(--severity-medium)' }}>
                  Could not compute risk delta for these versions (analysis request was denied or failed) — showing
                  structural changes only.
                </div>
              )}
              {riskDelta && (
                <div className="mb-3">
                  <div className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--text-secondary)' }}>
                    Risk delta
                  </div>
                  <div className="flex gap-4 text-sm">
                    {SEVERITIES.map((s) => {
                      const delta = riskDelta.after[s] - riskDelta.before[s]
                      return (
                        <span key={s} style={{ color: 'var(--text-primary)' }}>
                          {s}: {riskDelta.before[s]} → {riskDelta.after[s]}{' '}
                          <span style={{ color: delta > 0 ? 'var(--severity-critical)' : delta < 0 ? 'var(--severity-low)' : 'var(--text-secondary)' }}>
                            ({delta > 0 ? '+' : ''}
                            {delta})
                          </span>
                        </span>
                      )
                    })}
                  </div>
                </div>
              )}
              <div className="text-xs font-semibold uppercase tracking-wide mb-1" style={{ color: 'var(--text-secondary)' }}>
                Changes ({changeCount})
              </div>
              {changeCount === 0 && (
                <div className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  No structural changes between these versions.
                </div>
              )}
              {diff && (
                <div className="flex flex-col gap-1 text-sm">
                  {[...diff.components, ...diff.trustBoundaries, ...diff.dataFlows].map((entry) => (
                    <div key={`${entry.status}-${entry.id}`} className="flex items-center gap-2">
                      <span style={{ color: STATUS_COLOR[entry.status] }}>{STATUS_LABEL[entry.status]}</span>
                      <span style={{ color: 'var(--text-primary)' }}>{entry.label}</span>
                      {entry.changedFields && (
                        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                          ({entry.changedFields.join(', ')})
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
