import { useState } from 'react'
import type { Finding, KbBundle } from '../api/types'
import { RuleTrace } from './RuleTrace'

// Deliberately one neutral color for all three chips: "high" is good for
// effectiveness but bad for cost/effort, so a shared low→green/high→red
// scale would mislabel two of the three.
function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded-full" style={{ background: 'var(--surface-2)', color: 'var(--text-secondary)' }}>
      {label}: {value}
    </span>
  )
}

export function FindingCard({
  finding,
  kb,
  onSelectSubject,
}: {
  finding: Finding
  kb: KbBundle | undefined
  onSelectSubject: (subject: string) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const threat = kb?.threats[finding.threatId]
  const standards = threat?.standards
  const standardsLabels = [
    ...(standards?.cwe ?? []).map((id) => `CWE-${id}`),
    ...(standards?.capec ?? []).map((id) => `CAPEC-${id}`),
    ...(standards?.owasp_asvs ?? []).map((id) => `ASVS ${id}`),
    ...(standards?.owasp_top10_2021 ?? []).map((id) => `OWASP ${id}`),
    ...(standards?.pci_dss_4 ?? []).map((id) => `PCI-DSS ${id}`),
    ...(standards?.mitre_attack ?? []).map((id) => `ATT&CK ${id}`),
    ...(standards?.iso_27001_2022 ?? []).map((id) => `ISO 27001 ${id}`),
    ...(standards?.nist_800_53 ?? []).map((id) => `NIST 800-53 ${id}`),
  ]
  const countermeasures = finding.countermeasureIds.map((id) => kb?.countermeasures[id]).filter(Boolean)

  return (
    <div
      className="rounded-lg border p-3 cursor-pointer"
      style={{ borderColor: 'var(--border)', background: 'var(--surface-0)' }}
      onClick={() => onSelectSubject(finding.subject)}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
          {finding.title}
        </div>
        <span className="severity-badge shrink-0" data-severity={finding.severity}>
          {finding.severity}
        </span>
      </div>
      <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
        {finding.description}
      </div>
      <div className="text-[10px] mt-1" style={{ color: 'var(--text-secondary)' }}>
        {finding.subject} · {finding.ruleId}
      </div>
      {standardsLabels.length > 0 && (
        <div className="text-[10px] mt-1" style={{ color: 'var(--text-secondary)' }}>
          {standardsLabels.join(' · ')}
        </div>
      )}

      {(finding.trace || countermeasures.length > 0) && (
        <button
          className="text-xs mt-2 underline"
          style={{ color: 'var(--accent)' }}
          onClick={(e) => {
            e.stopPropagation()
            setExpanded((v) => !v)
          }}
        >
          {expanded ? 'Hide details' : 'Why did this fire? / How to fix'}
        </button>
      )}

      {expanded && (
        <div onClick={(e) => e.stopPropagation()}>
          {finding.trace && <RuleTrace trace={finding.trace} />}

          {countermeasures.length > 0 && (
            <div className="mt-2 flex flex-col gap-2">
              <div className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>
                Recommended countermeasures
              </div>
              {countermeasures.map((cm) => (
                <div key={cm!.metadata.id} className="text-xs rounded p-2" style={{ background: 'var(--surface-1)' }}>
                  <div className="font-medium" style={{ color: 'var(--text-primary)' }}>
                    {cm!.title}
                  </div>
                  <div className="mt-0.5" style={{ color: 'var(--text-secondary)' }}>
                    {cm!.description}
                  </div>
                  <div className="flex gap-1 mt-1.5 flex-wrap">
                    <Chip label="Cost" value={cm!.cost} />
                    <Chip label="Effort" value={cm!.effort} />
                    <Chip label="Effectiveness" value={cm!.effectiveness} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
