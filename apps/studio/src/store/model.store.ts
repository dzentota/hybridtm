import { create, useStore } from 'zustand'
import { useShallow } from 'zustand/react/shallow'
import { temporal } from 'zundo'
import type { Edge, Node } from '@xyflow/react'
import type {
  CanonicalDataFlow,
  CanonicalModel,
  Finding,
  KbComponent,
  PropertyBag,
  PropertyValue,
} from '../api/types'

export interface ComponentNodeData extends Record<string, unknown> {
  kind: 'component'
  name: string
  kbComponentId?: string
  kbName?: string
  kbVersion?: string
  traits: string[]
  properties: PropertyBag
  findingCount: number
  maxSeverity?: Finding['severity']
}

export interface BoundaryNodeData extends Record<string, unknown> {
  kind: 'boundary'
  name: string
  boundaryType: string
}

export type StudioNode = Node<ComponentNodeData | BoundaryNodeData>

export interface DataFlowEdgeData extends Record<string, unknown> {
  protocol?: string
  crossesBoundary?: boolean
  maxSeverity?: Finding['severity']
}

export type StudioEdge = Edge<DataFlowEdgeData>

let nextId = 1
function freshId(prefix: string): string {
  return `${prefix}-${nextId++}`
}

const AUTOSAVE_KEY = 'hybridtm.studio.autosave.v1'

interface AutosavePayload {
  title: string
  nodes: StudioNode[]
  edges: StudioEdge[]
  savedAt: string
}

interface ModelState {
  title: string
  nodes: StudioNode[]
  edges: StudioEdge[]
  selectedId: string | null
  findings: Finding[]
  lastSavedAt: string | null

  setNodes: (updater: (nodes: StudioNode[]) => StudioNode[]) => void
  setEdges: (updater: (edges: StudioEdge[]) => StudioEdge[]) => void
  select: (id: string | null) => void
  setTitle: (title: string) => void

  addComponentFromKb: (kbId: string, kb: KbComponent, position: { x: number; y: number }) => void
  addBoundary: (position: { x: number; y: number }) => void
  updateProperty: (nodeId: string, propertyId: string, value: PropertyValue) => void
  connect: (sourceId: string, targetId: string) => void

  applyFindings: (findings: Finding[]) => void
  toCanonicalModel: () => CanonicalModel
  loadCanonicalModel: (model: CanonicalModel) => void
  markSaved: (at: string) => void
}

type TemporalSlice = Pick<ModelState, 'title' | 'nodes' | 'edges'>

export const useModelStore = create<ModelState>()(
  temporal<ModelState, [], [], TemporalSlice>(
    (set, get) => ({
      title: 'Untitled model',
      nodes: [],
      edges: [],
      selectedId: null,
      findings: [],
      lastSavedAt: null,

      setNodes: (updater) => set((s) => ({ nodes: updater(s.nodes) })),
      setEdges: (updater) => set((s) => ({ edges: updater(s.edges) })),
      select: (id) => set({ selectedId: id }),
      setTitle: (title) => set({ title }),

      addComponentFromKb: (kbId, kb, position) => {
        const id = freshId(kbId.replace(/[^a-z0-9]/gi, '-'))
        const properties: PropertyBag = {}
        for (const prop of kb.properties) {
          if (prop.default !== undefined) properties[prop.id] = prop.default
        }
        const node: StudioNode = {
          id,
          type: 'component',
          position,
          data: {
            kind: 'component',
            name: kb.metadata.name,
            kbComponentId: kbId,
            kbName: kb.metadata.name,
            kbVersion: kb.metadata.version,
            traits: kb.traits,
            properties,
            findingCount: 0,
          },
        }
        set((s) => ({ nodes: [...s.nodes, node] }))
      },

      addBoundary: (position) => {
        const id = freshId('boundary')
        const node: StudioNode = {
          id,
          type: 'boundary',
          position,
          style: { width: 420, height: 260 },
          data: { kind: 'boundary', name: 'Trust boundary', boundaryType: 'network-cloud-provider' },
        }
        set((s) => ({ nodes: [...s.nodes, node] }))
      },

      updateProperty: (nodeId, propertyId, value) => {
        set((s) => ({
          nodes: s.nodes.map((n) =>
            n.id === nodeId && n.data.kind === 'component'
              ? { ...n, data: { ...n.data, properties: { ...n.data.properties, [propertyId]: value } } }
              : n,
          ),
        }))
      },

      connect: (sourceId, targetId) => {
        const id = freshId('flow')
        set((s) => ({
          edges: [
            ...s.edges,
            { id, source: sourceId, target: targetId, type: 'dataflow', data: {} },
          ],
        }))
      },

      applyFindings: (findings) => {
        const bySubject = new Map<string, Finding[]>()
        for (const f of findings) {
          const list = bySubject.get(f.subject) ?? []
          list.push(f)
          bySubject.set(f.subject, list)
        }
        const severityRank: Record<Finding['severity'], number> = {
          low: 0,
          medium: 1,
          elevated: 2,
          high: 3,
          critical: 4,
        }
        const maxOf = (list: Finding[]) =>
          list.reduce<Finding['severity']>(
            (max, f) => (severityRank[f.severity] > severityRank[max] ? f.severity : max),
            'low',
          )

        set((s) => ({
          findings,
          nodes: s.nodes.map((n) => {
            if (n.data.kind !== 'component') return n
            const list = bySubject.get(`component:${n.id}`) ?? []
            return {
              ...n,
              data: { ...n.data, findingCount: list.length, maxSeverity: list.length ? maxOf(list) : undefined },
            }
          }),
          edges: s.edges.map((e) => {
            const list = bySubject.get(`flow:${e.id}`) ?? []
            return { ...e, data: { ...e.data, maxSeverity: list.length ? maxOf(list) : undefined } }
          }),
        }))
      },

      toCanonicalModel: () => {
        const { title, nodes, edges } = get()
        const componentNodes = nodes.filter(
          (n): n is StudioNode & { data: ComponentNodeData } => n.data.kind === 'component',
        )
        const boundaryNodes = nodes.filter(
          (n): n is StudioNode & { data: BoundaryNodeData } => n.data.kind === 'boundary',
        )

        const boundaryOf = (nodeId: string): string | undefined => {
          const node = nodes.find((n) => n.id === nodeId)
          return node?.parentId
        }

        const dataFlows: CanonicalDataFlow[] = edges.map((e) => ({
          id: e.id,
          sourceId: e.source,
          targetId: e.target,
          protocol: e.data?.protocol ?? 'unknown-protocol',
        }))

        return {
          schemaVersion: 1,
          model: { title, businessCriticality: 'important' },
          dataAssets: [],
          components: componentNodes.map((n) => ({
            id: n.id,
            name: n.data.name,
            kbComponent: n.data.kbComponentId,
            kbVersion: n.data.kbVersion,
            properties: n.data.properties,
            traits: n.data.traits,
            overrides: {},
          })),
          trustBoundaries: boundaryNodes.map((n) => ({
            id: n.id,
            name: n.data.name,
            type: n.data.boundaryType,
            contains: componentNodes.filter((c) => boundaryOf(c.id) === n.id).map((c) => c.id),
            nested: [],
          })),
          dataFlows,
        }
      },

      loadCanonicalModel: (model) => {
        const boundaryNodes: StudioNode[] = model.trustBoundaries.map((b, i) => ({
          id: b.id,
          type: 'boundary',
          position: { x: 40 + i * 40, y: 40 + i * 40 },
          style: { width: 420, height: 260 },
          data: { kind: 'boundary', name: b.name, boundaryType: b.type },
        }))
        const boundaryOfComponent = new Map<string, string>()
        for (const b of model.trustBoundaries) {
          for (const cid of b.contains) boundaryOfComponent.set(cid, b.id)
        }
        const componentNodes: StudioNode[] = model.components.map((c, i) => ({
          id: c.id,
          type: 'component',
          position: { x: 80 + (i % 5) * 180, y: 340 + Math.floor(i / 5) * 140 },
          parentId: boundaryOfComponent.get(c.id),
          data: {
            kind: 'component',
            name: c.name,
            kbComponentId: c.kbComponent,
            kbVersion: c.kbVersion,
            traits: c.traits,
            properties: c.properties,
            findingCount: 0,
          },
        }))
        const edges: StudioEdge[] = model.dataFlows.map((f) => ({
          id: f.id ?? freshId('flow'),
          source: f.sourceId,
          target: f.targetId,
          type: 'dataflow',
          data: { protocol: f.protocol },
        }))
        set({
          title: model.model.title,
          nodes: [...boundaryNodes, ...componentNodes],
          edges,
          selectedId: null,
          findings: [],
        })
      },

      markSaved: (at) => set({ lastSavedAt: at }),
    }),
    {
      limit: 50,
      equality: (a, b) => a.nodes === b.nodes && a.edges === b.edges && a.title === b.title,
      partialize: (state) => ({ title: state.title, nodes: state.nodes, edges: state.edges }),
    },
  ),
)

export function useTemporalStore() {
  return useStore(
    useModelStore.temporal,
    useShallow((s) => ({
      undo: s.undo,
      redo: s.redo,
      canUndo: s.pastStates.length > 0,
      canRedo: s.futureStates.length > 0,
    })),
  )
}

function readAutosave(): AutosavePayload | null {
  try {
    const raw = localStorage.getItem(AUTOSAVE_KEY)
    return raw ? (JSON.parse(raw) as AutosavePayload) : null
  } catch {
    return null
  }
}

export function restoreAutosave(): AutosavePayload | null {
  return readAutosave()
}

export function clearAutosave(): void {
  localStorage.removeItem(AUTOSAVE_KEY)
  useModelStore.setState({ lastSavedAt: null })
}

let autosaveTimeout: ReturnType<typeof setTimeout> | undefined
useModelStore.subscribe((state, prevState) => {
  if (state.nodes === prevState.nodes && state.edges === prevState.edges && state.title === prevState.title) return
  if (autosaveTimeout) clearTimeout(autosaveTimeout)
  autosaveTimeout = setTimeout(() => {
    const { title, nodes, edges } = useModelStore.getState()
    const savedAt = new Date().toISOString()
    const payload: AutosavePayload = { title, nodes, edges, savedAt }
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(payload))
    useModelStore.getState().markSaved(savedAt)
  }, 800)
})
