import { useState } from 'react'
import type { Finding } from '../api/types'
import { RuleTrace } from './RuleTrace'

export function FindingCard({ finding, onSelectSubject }: { finding: Finding; onSelectSubject: (subject: string) => void }) {
  const [expanded, setExpanded] = useState(false)

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

      {finding.trace && (
        <button
          className="text-xs mt-2 underline"
          style={{ color: 'var(--accent)' }}
          onClick={(e) => {
            e.stopPropagation()
            setExpanded((v) => !v)
          }}
        >
          {expanded ? 'Hide reasoning' : 'Why did this fire?'}
        </button>
      )}
      {expanded && finding.trace && <RuleTrace trace={finding.trace} />}
    </div>
  )
}
