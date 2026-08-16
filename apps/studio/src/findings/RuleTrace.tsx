import type { RuleTrace as RuleTraceType } from '../api/types'

/** "Why did this fire?" condition-by-condition breakdown (T-7.11) — the
 * plan calls this out specifically as what earns trust in an automated
 * threat model; a finding with no visible reasoning reads as a black box. */
export function RuleTrace({ trace }: { trace: RuleTraceType }) {
  return (
    <div className="mt-2 text-xs font-mono flex flex-col gap-1">
      {trace.conditions.map((c, i) => (
        <div key={i} className="flex items-start gap-1.5">
          <span style={{ color: c.passed ? 'var(--severity-medium)' : 'var(--text-secondary)' }}>
            {c.passed ? '✓' : '✗'}
          </span>
          <span style={{ color: 'var(--text-secondary)' }}>
            {c.kind === 'unless' && '[unless] '}
            {c.expression}
          </span>
        </div>
      ))}
    </div>
  )
}
