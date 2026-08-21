import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useModelStore } from '../store/model.store'
import { FindingCard } from './FindingCard'
import type { KbBundle } from '../api/types'

const severityOrder = ['critical', 'high', 'elevated', 'medium', 'low'] as const

/** Findings list with severity filter + grouping, wired to canvas selection
 * (T-7.10): clicking a card selects the node/edge it's about. */
export function FindingsPanel({
  kb,
  onRunAnalysis,
  isAnalyzing,
  analysisError,
}: {
  kb: KbBundle | undefined
  onRunAnalysis: () => void
  isAnalyzing: boolean
  analysisError: string | null
}) {
  const { t } = useTranslation()
  const { findings, select, focusSubjectId, setFocusSubject, nodes, storyCoverage } = useModelStore()
  const [minSeverity, setMinSeverity] = useState<(typeof severityOrder)[number]>('low')

  const focusName = focusSubjectId ? nodes.find((n) => n.id === focusSubjectId)?.data.name : undefined

  const bySeverity = useMemo(() => {
    const cutoff = severityOrder.indexOf(minSeverity)
    return findings.filter((f) => severityOrder.indexOf(f.severity as (typeof severityOrder)[number]) <= cutoff)
  }, [findings, minSeverity])

  const visible = useMemo(
    () => bySeverity.filter((f) => !focusSubjectId || f.subject === `component:${focusSubjectId}`),
    [bySeverity, focusSubjectId],
  )

  const grouped = useMemo(() => {
    const map = new Map<string, typeof findings>()
    for (const f of visible) {
      const list = map.get(f.severity) ?? []
      list.push(f)
      map.set(f.severity, list)
    }
    return map
  }, [visible])

  return (
    <div className="flex flex-col h-full min-h-0" style={{ background: 'var(--surface-1)', borderLeft: '1px solid var(--border)' }}>
      <div className="p-3 flex flex-col gap-2 shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        <button
          onClick={onRunAnalysis}
          disabled={isAnalyzing}
          className="text-sm font-medium px-3 py-1.5 rounded"
          style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
        >
          {isAnalyzing ? t('findings.analyzing') : t('findings.runAnalysis')}
        </button>
        {analysisError && (
          <div className="text-xs" style={{ color: 'var(--severity-critical)' }} role="alert">
            Analysis failed: {analysisError}
          </div>
        )}
        {focusSubjectId && (
          <div
            className="flex items-center justify-between gap-2 text-xs px-2 py-1 rounded-full"
            style={{ background: 'var(--surface-2)', color: 'var(--text-primary)' }}
          >
            <span className="truncate">
              Showing {visible.length} of {bySeverity.length} findings for {focusName ?? 'selected component'}
            </span>
            <button type="button" className="font-medium shrink-0" style={{ color: 'var(--accent)' }} onClick={() => setFocusSubject(null)}>
              Clear
            </button>
          </div>
        )}
        {storyCoverage.some((c) => c.status === 'uncovered' || c.status === 'partial') && (
          <div className="text-xs px-2 py-1 rounded" style={{ background: 'var(--surface-2)', color: 'var(--severity-critical)' }}>
            {storyCoverage.filter((c) => c.status === 'uncovered' || c.status === 'partial').length} Abuser Stor
            {storyCoverage.filter((c) => c.status === 'uncovered' || c.status === 'partial').length === 1 ? 'y' : 'ies'} still uncovered — check the
            Stories tab.
          </div>
        )}
        <select
          value={minSeverity}
          onChange={(e) => setMinSeverity(e.target.value as (typeof severityOrder)[number])}
          className="text-xs px-2 py-1 rounded border"
          style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
        >
          {severityOrder.map((s) => (
            <option key={s} value={s}>
              {t('findings.minSeverity', { severity: s })}
            </option>
          ))}
        </select>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto p-3 flex flex-col gap-3">
        {findings.length === 0 && (
          <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            {t('findings.empty')}
          </div>
        )}
        {findings.length > 0 && visible.length === 0 && (
          <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            {focusSubjectId
              ? `No findings for ${focusName ?? 'this component'} at or above the selected severity.`
              : 'No findings at or above the selected severity.'}
          </div>
        )}
        {severityOrder
          .filter((s) => grouped.has(s))
          .map((severity) => (
            <div key={severity}>
              <div className="text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                {severity} ({grouped.get(severity)!.length})
              </div>
              <div className="flex flex-col gap-2">
                {grouped.get(severity)!.map((f) => (
                  <FindingCard
                    key={f.stableId}
                    finding={f}
                    kb={kb}
                    onSelectSubject={(subject) => {
                      const id = subject.split(':')[1]
                      if (id) select(id)
                    }}
                  />
                ))}
              </div>
            </div>
          ))}
      </div>
    </div>
  )
}
