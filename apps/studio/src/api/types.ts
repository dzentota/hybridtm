// Mirrors canonical-model.v1.json (repo root) — kept intentionally partial,
// only the fields the MVP canvas/inspector/findings loop actually reads or
// writes. Extend as later E7 tasks need more of the schema.

export type PropertyValue = string | number | boolean | null | string[]

export interface PropertyBag {
  [key: string]: PropertyValue
}

export interface CanonicalComponent {
  id: string
  name: string
  description?: string
  kbComponent?: string
  kbVersion?: string
  properties: PropertyBag
  traits: string[]
  overrides: Record<string, unknown>
  dataAssetsProcessed?: string[]
  dataAssetsStored?: string[]
  tags?: string[]
}

export interface CanonicalTrustBoundary {
  id: string
  name: string
  description?: string
  type: string
  contains: string[]
  nested: string[]
  tags?: string[]
}

export interface CanonicalDataFlow {
  id?: string
  sourceId: string
  targetId: string
  sourcePort?: string
  targetPort?: string
  description?: string
  protocol?: string
}

export interface CanonicalModel {
  schemaVersion: 1
  kbVersion?: string
  model: { title: string; businessCriticality?: string }
  dataAssets: unknown[]
  components: CanonicalComponent[]
  trustBoundaries: CanonicalTrustBoundary[]
  dataFlows: CanonicalDataFlow[]
  sharedRuntimes?: unknown[]
  riskTracking?: unknown[]
  questions?: unknown[]
  abuseCases?: unknown[]
  securityRequirements?: unknown[]
}

// ---- KB bundle (GET /kb/bundle) ----

export interface KbPropertyDef {
  id: string
  label: string
  type: 'boolean' | 'string' | 'number' | 'enum' | 'array'
  default?: PropertyValue
  enum?: string[]
  group?: string
  show_if?: Record<string, unknown>
  hint?: string
}

export interface KbComponent {
  mapping: { type: string; technologies?: string[]; machine?: string }
  traits: string[]
  properties: KbPropertyDef[]
  rules: string[]
  metadata: {
    id: string
    name: string
    version: string
    vendor?: string
    categories?: string[]
    maturity?: string
  }
}

export interface KbBundle {
  kbVersion: string
  traits: Record<string, unknown>
  components: Record<string, KbComponent>
  threats: Record<string, unknown>
  countermeasures: Record<string, unknown>
  rules: Record<string, unknown>
  riskPatterns: Record<string, unknown>
  templates: Record<string, unknown>
}

// ---- Analysis results (POST /model-versions/{id}/analyze) ----

export interface RuleTraceCondition {
  expression: string
  passed: boolean
  kind: 'when' | 'unless'
  detail: string
}

export interface RuleTrace {
  ruleId: string
  matched: boolean
  conditions: RuleTraceCondition[]
}

export interface Finding {
  stableId: string
  threatId: string
  ruleId: string
  source: string
  subject: string // "component:<id>" | "flow:<id>" | "boundary:<id>"
  title: string
  description: string
  likelihood: string
  impact: string
  severity: 'low' | 'medium' | 'elevated' | 'high' | 'critical'
  stride: string[]
  evidence: string[]
  countermeasureIds: string[]
  trace: RuleTrace | null
}

export interface AnalysisResult {
  findings: Finding[]
  validation: { issues: unknown[]; hasErrors: boolean; counts: Record<string, number> }
  summary: Record<string, number>
}
