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
  // Mirrors CommunicationLink.dataSent/dataReceived/tags (src/DSL/CommunicationLink.php)
  // — IDs into CanonicalModel.dataAssets. No separate "direction" field:
  // a flow that only sends is outbound, one that only receives is inbound,
  // one with both is bidirectional (request/response).
  dataSent?: string[]
  dataReceived?: string[]
  tags?: string[]
}

// Mirrors src/DSL/DataAsset.php (only the fields the studio surfaces —
// backend has richer classification: usage/origin/owner/quantity/CIA
// ratings — extend here as the UI grows into them).
export interface CanonicalDataAsset {
  id: string
  name: string
  classification?: string
  tags?: string[]
}

// Mirrors src/Codec/LayoutCodec.php's `threat-model.layout.json` shape — a
// sidecar for canvas pixel positions, deliberately separate from
// CanonicalModel (which has no notion of where things sit on screen).
// ModelVersion.layout on the backend is this exact shape, keyed by
// component/boundary id.
export interface LayoutRect {
  x: number
  y: number
  w: number
  h: number
}

export interface LayoutGroup extends LayoutRect {
  collapsed: boolean
}

export interface ModelLayout {
  schemaVersion: 1
  nodes: Record<string, LayoutRect>
  groups: Record<string, LayoutGroup>
  edges: Record<string, [number, number][]>
  viewport: { x: number; y: number; zoom: number }
}

export interface CanonicalModel {
  schemaVersion: 1
  kbVersion?: string
  model: { title: string; businessCriticality?: string }
  dataAssets: CanonicalDataAsset[]
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
    icon?: string
    color?: string
  }
}

export interface KbCountermeasure {
  title: string
  description: string
  cost: 'low' | 'medium' | 'high'
  effort: 'low' | 'medium' | 'high'
  effectiveness: 'low' | 'medium' | 'high'
  category: string
  metadata: { id: string; version: string }
}

export interface KbThreat {
  title: string
  summary: string
  stride: string[]
  base: { likelihood: string; impact: string }
  // Mirrors schema/kb/threat.v1.json's `standards` shape — populated
  // per-threat only where a mapping has actually been verified against the
  // primary source (MITRE CAPEC, OWASP ASVS GitHub, etc.), not guessed;
  // most threats still only carry `cwe`, and that's fine — an absent field
  // means "not yet mapped," not "not applicable."
  standards?: {
    cwe?: number[]
    capec?: number[]
    owasp_top10_2021?: string[]
    owasp_asvs?: string[]
    mitre_attack?: string[]
    pci_dss_4?: string[]
    iso_27001_2022?: string[]
    nist_800_53?: string[]
  }
  countermeasures: string[]
  metadata: { id: string; version: string }
}

export interface KbBundle {
  kbVersion: string
  traits: Record<string, unknown>
  components: Record<string, KbComponent>
  threats: Record<string, KbThreat>
  countermeasures: Record<string, KbCountermeasure>
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
