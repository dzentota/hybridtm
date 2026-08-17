import type { CanonicalModel, PropertyBag } from '../api/types'

export interface EntryDiff {
  id: string
  label: string
  status: 'added' | 'removed' | 'changed'
  changedFields?: string[]
}

export interface ModelDiff {
  components: EntryDiff[]
  trustBoundaries: EntryDiff[]
  dataFlows: EntryDiff[]
}

function propertyDiff(a: PropertyBag, b: PropertyBag): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)])
  const changed: string[] = []
  for (const key of keys) {
    if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) changed.push(key)
  }
  return changed
}

/** Pure structural diff (T-7.22) — every entity compared by stable id, not
 * position: two versions with the same components rearranged on the
 * canvas show zero changes, which is the point of a threat-model diff
 * (what changed about the *system*, not where someone dragged a box). */
export function computeModelDiff(from: CanonicalModel, to: CanonicalModel): ModelDiff {
  // As in canonicalModelToGraph (model.store.ts): CanonicalModel declares
  // these arrays required, but stored data doesn't always comply (e.g. a
  // PHP-DSL-imported version with no trustBoundaries/dataFlows keys at
  // all, or components missing `properties`) — default rather than trust
  // the type when reading arbitrary saved versions.
  const components: EntryDiff[] = []
  const fromComponents = new Map((from.components ?? []).map((c) => [c.id, c]))
  const toComponents = new Map((to.components ?? []).map((c) => [c.id, c]))
  for (const [id, c] of fromComponents) {
    if (!toComponents.has(id)) components.push({ id, label: c.name, status: 'removed' })
  }
  for (const [id, c] of toComponents) {
    const before = fromComponents.get(id)
    if (!before) {
      components.push({ id, label: c.name, status: 'added' })
      continue
    }
    const changedFields = propertyDiff(before.properties ?? {}, c.properties ?? {})
    if (before.name !== c.name) changedFields.unshift('name')
    if (before.kbVersion !== c.kbVersion) changedFields.push('kbVersion')
    if (changedFields.length > 0) components.push({ id, label: c.name, status: 'changed', changedFields })
  }

  const trustBoundaries: EntryDiff[] = []
  const fromBoundaries = new Map((from.trustBoundaries ?? []).map((b) => [b.id, b]))
  const toBoundaries = new Map((to.trustBoundaries ?? []).map((b) => [b.id, b]))
  for (const [id, b] of fromBoundaries) {
    if (!toBoundaries.has(id)) trustBoundaries.push({ id, label: b.name, status: 'removed' })
  }
  for (const [id, b] of toBoundaries) {
    if (!fromBoundaries.has(id)) trustBoundaries.push({ id, label: b.name, status: 'added' })
  }

  const flowKey = (f: CanonicalModel['dataFlows'][number]) => f.id ?? `${f.sourceId}->${f.targetId}`
  const dataFlows: EntryDiff[] = []
  const fromFlows = new Map((from.dataFlows ?? []).map((f) => [flowKey(f), f]))
  const toFlows = new Map((to.dataFlows ?? []).map((f) => [flowKey(f), f]))
  for (const [key, f] of fromFlows) {
    if (!toFlows.has(key)) dataFlows.push({ id: key, label: `${f.sourceId} → ${f.targetId}`, status: 'removed' })
  }
  for (const [key, f] of toFlows) {
    if (!fromFlows.has(key)) dataFlows.push({ id: key, label: `${f.sourceId} → ${f.targetId}`, status: 'added' })
  }

  return { components, trustBoundaries, dataFlows }
}

export interface RiskDelta {
  before: Record<string, number>
  after: Record<string, number>
}

const SEVERITIES = ['critical', 'high', 'elevated', 'medium', 'low'] as const

export function computeRiskDelta(
  beforeFindings: { severity: string }[],
  afterFindings: { severity: string }[],
): RiskDelta {
  const count = (findings: { severity: string }[]) => {
    const tally: Record<string, number> = Object.fromEntries(SEVERITIES.map((s) => [s, 0]))
    for (const f of findings) tally[f.severity] = (tally[f.severity] ?? 0) + 1
    return tally
  }
  return { before: count(beforeFindings), after: count(afterFindings) }
}
