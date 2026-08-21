import { create, useStore } from 'zustand'
import { useShallow } from 'zustand/react/shallow'
import { temporal } from 'zundo'
import type { Edge, Node } from '@xyflow/react'
import type {
  CanonicalAbuserStory,
  CanonicalDataAsset,
  CanonicalDataFlow,
  CanonicalModel,
  Finding,
  KbComponent,
  LayoutGroup,
  LayoutRect,
  ModelLayout,
  PropertyBag,
  PropertyValue,
  StoryCoverage,
} from '../api/types'

export interface ComponentNodeData extends Record<string, unknown> {
  kind: 'component'
  name: string
  kbComponentId?: string
  kbName?: string
  kbVersion?: string
  icon?: string
  color?: string
  traits: string[]
  properties: PropertyBag
  findingCount: number
  maxSeverity?: Finding['severity']
}

// Icon/color aren't part of CanonicalModel (they're KB-only display
// metadata), so a component built from a saved model version — loadCanonicalModel,
// PHP import, diff-preview canvases — has no icon of its own to carry. This
// index, filled once the KB bundle loads (see App.tsx), lets every node-
// building path (including the pure canonicalModelToGraph, which has no kb
// bundle in scope) look icons up by kbComponentId instead of threading the
// bundle through every call site.
let kbIconIndex: Record<string, { icon?: string; color?: string }> = {}
export function setKbIconIndex(components: Record<string, KbComponent>): void {
  kbIconIndex = Object.fromEntries(
    Object.entries(components).map(([id, c]) => [id, { icon: c.metadata.icon, color: c.metadata.color }]),
  )
}

export interface BoundaryNodeData extends Record<string, unknown> {
  kind: 'boundary'
  name: string
  boundaryType: string
}

export type StudioNode = Node<ComponentNodeData | BoundaryNodeData>

export interface DataFlowEdgeData extends Record<string, unknown> {
  protocol?: string
  maxSeverity?: Finding['severity']
  // Mirrors CommunicationLink.dataSent/dataReceived (src/DSL/CommunicationLink.php)
  // — IDs into the model's data-asset library. A flow's "direction" isn't a
  // separate field: which assets it *sends* (source→target) vs *receives*
  // (the response, target→source) already implies it, and matches what the
  // backend DSL actually models rather than adding a redundant enum.
  dataSent?: string[]
  dataReceived?: string[]
  tags?: string[]
}

export type StudioEdge = Edge<DataFlowEdgeData>

export type OverlayMode = 'risks' | 'data' | 'exposure' | 'coverage'

let nextId = 1
function freshId(prefix: string): string {
  return `${prefix}-${nextId++}`
}

// xyflow bumps a node's z-index above its siblings on select/drag
// (elevateNodesOnSelect) — fine for ordinary nodes, but a boundary is a
// *container*: elevating it above its own children on selection/drag put
// the boundary's fill on top of the component that had just been dropped
// into it, hiding it and forcing you to move the boundary out of the way
// to get the component back. Explicit, fixed zIndex + `zIndexMode="manual"`
// on <ReactFlow> (FlowCanvas.tsx) turns that automatic elevation off
// entirely, so boundaries always render behind components regardless of
// selection order.
const BOUNDARY_Z_INDEX = 0
const COMPONENT_Z_INDEX = 1

// Matches ComponentNode.tsx's fixed `w-[220px] h-[96px]` — the layout
// sidecar records a size per LayoutCodec's shape, but the canvas doesn't
// support resizing components, so it's always this constant.
const COMPONENT_LAYOUT_SIZE = { w: 220, h: 96 }
const DEFAULT_BOUNDARY_SIZE = { w: 420, h: 260 }

/** A child node's `position` is relative to its parent in xyflow; the
 * layout sidecar (and everything else that reasons about "where is this on
 * the canvas") wants absolute canvas coordinates. Exported so FlowCanvas's
 * drop-into-boundary logic and the layout writer share one conversion. */
export function absolutePosition(node: StudioNode, allNodes: StudioNode[]): { x: number; y: number } {
  if (!node.parentId) return node.position
  const parent = allNodes.find((n) => n.id === node.parentId)
  if (!parent) return node.position
  return { x: parent.position.x + node.position.x, y: parent.position.y + node.position.y }
}

/** Pure CanonicalModel → {nodes, edges} conversion, shared by
 * `loadCanonicalModel` and the version-diff preview canvases (T-7.22) —
 * neither should re-derive this layout logic independently. `layout` is the
 * ModelVersion's sidecar of saved canvas positions (see toLayout below); a
 * component/boundary with no entry in it falls back to a deterministic
 * grid, same as models saved before layout persistence existed. */
export function canonicalModelToGraph(
  model: CanonicalModel,
  layout?: ModelLayout | null,
): { nodes: StudioNode[]; edges: StudioEdge[] } {
  // CanonicalModel declares components/trustBoundaries/dataFlows required,
  // but stored data doesn't always comply — models saved via the PHP DSL
  // import, or by tooling that predates a given field, can omit any of
  // these top-level arrays entirely (seen with a project whose ModelVersion
  // had no `trustBoundaries`/`dataFlows` keys at all, only `components`).
  const trustBoundaries = model.trustBoundaries ?? []
  const components = model.components ?? []
  const dataFlows = model.dataFlows ?? []

  // Fallback grid for boundaries with no saved position (models imported
  // from PHP/Threagile/OTM never carry a layout sidecar at all — see
  // ImportController, which only ever sets `data`, never `layout`). This
  // used to place boundary *i* at (40+40i, 40+40i) with every box the same
  // DEFAULT_BOUNDARY_SIZE — a diagonal staircase of identically-sized boxes
  // reads as nested concentric rectangles, not as siblings, which is
  // exactly the "trust zones nested inside each other" bug reported after
  // a PHP DSL round-trip. Laying them out in a row (wrapping every 3)
  // keeps them visually independent instead.
  const BOUNDARY_GAP = 40
  const BOUNDARIES_PER_ROW = 3
  const boundaryNodes: StudioNode[] = trustBoundaries.map((b, i) => {
    const saved = layout?.groups[b.id]
    const col = i % BOUNDARIES_PER_ROW
    const row = Math.floor(i / BOUNDARIES_PER_ROW)
    return {
      id: b.id,
      type: 'boundary',
      position: saved
        ? { x: saved.x, y: saved.y }
        : {
            x: 40 + col * (DEFAULT_BOUNDARY_SIZE.w + BOUNDARY_GAP),
            y: 40 + row * (DEFAULT_BOUNDARY_SIZE.h + BOUNDARY_GAP),
          },
      style: saved ? { width: saved.w, height: saved.h } : { width: DEFAULT_BOUNDARY_SIZE.w, height: DEFAULT_BOUNDARY_SIZE.h },
      zIndex: BOUNDARY_Z_INDEX,
      data: { kind: 'boundary', name: b.name, boundaryType: b.type },
    }
  })
  const boundaryOfComponent = new Map<string, string>()
  for (const b of trustBoundaries) {
    for (const cid of b.contains ?? []) boundaryOfComponent.set(cid, b.id)
  }
  // Separate running index per parent (rather than the shared `i` from
  // .map): a child node's fallback position is relative to its *own*
  // parent boundary once parentId is set (xyflow treats a child's
  // `position` as parent-relative, unconditionally), so reusing the global
  // index — a page-scale absolute-looking offset like (80 + 4*180, 340) —
  // could place a child hundreds of pixels outside its own boundary's much
  // smaller box. That was the other half of the same reported bug: PHP
  // import produces no layout, so every component hit this fallback and
  // ended up stranded outside its trust zone instead of inside it.
  const childIndexInParent = new Map<string, number>()
  let topLevelIndex = 0
  const componentNodes: StudioNode[] = components.map((c) => {
    const kbIcon = c.kbComponent ? kbIconIndex[c.kbComponent] : undefined
    const parentId = boundaryOfComponent.get(c.id)
    const saved = layout?.nodes[c.id]
    // The sidecar stores absolute canvas coordinates; a child node's
    // position must be relative to its parent boundary's own (also saved)
    // position, or it'd render offset by the parent's coordinates too.
    const parentSaved = parentId ? layout?.groups[parentId] : undefined
    let position: { x: number; y: number }
    if (saved) {
      position = parentId && parentSaved ? { x: saved.x - parentSaved.x, y: saved.y - parentSaved.y } : { x: saved.x, y: saved.y }
    } else if (parentId) {
      const idx = childIndexInParent.get(parentId) ?? 0
      childIndexInParent.set(parentId, idx + 1)
      position = { x: 24 + (idx % 2) * 190, y: 48 + Math.floor(idx / 2) * 110 }
    } else {
      const idx = topLevelIndex++
      position = { x: 80 + (idx % 5) * 180, y: 340 + Math.floor(idx / 5) * 140 }
    }
    return {
      id: c.id,
      type: 'component',
      position,
      parentId,
      zIndex: COMPONENT_Z_INDEX,
      data: {
        kind: 'component',
        name: c.name,
        kbComponentId: c.kbComponent,
        kbVersion: c.kbVersion,
        icon: kbIcon?.icon,
        color: kbIcon?.color,
        // Some stored models predate `properties` (e.g. PHP-DSL-imported
        // components carry only traits/overrides) or were saved by another
        // client — CanonicalComponent declares these required, but real
        // data on disk doesn't always comply, so default rather than trust
        // the type here.
        traits: c.traits ?? [],
        properties: c.properties ?? {},
        findingCount: 0,
      },
    }
  })
  const edges: StudioEdge[] = dataFlows.map((f) => ({
    id: f.id ?? freshId('flow'),
    source: f.sourceId,
    target: f.targetId,
    sourceHandle: 'out',
    targetHandle: 'in',
    type: 'dataflow',
    data: { protocol: f.protocol, dataSent: f.dataSent ?? [], dataReceived: f.dataReceived ?? [], tags: f.tags ?? [] },
  }))
  return { nodes: [...boundaryNodes, ...componentNodes], edges }
}

function buildComponentNode(kbId: string, kb: KbComponent, position: { x: number; y: number }): StudioNode {
  const id = freshId(kbId.replace(/[^a-z0-9]/gi, '-'))
  const properties: PropertyBag = {}
  for (const prop of kb.properties) {
    if (prop.default !== undefined) properties[prop.id] = prop.default
  }
  return {
    id,
    type: 'component',
    position,
    zIndex: COMPONENT_Z_INDEX,
    ariaLabel: `${kb.metadata.name} component, no findings yet`,
    data: {
      kind: 'component',
      name: kb.metadata.name,
      kbComponentId: kbId,
      kbName: kb.metadata.name,
      kbVersion: kb.metadata.version,
      icon: kb.metadata.icon,
      color: kb.metadata.color,
      traits: kb.traits,
      properties,
      findingCount: 0,
    },
  }
}

// Keyed per project (not one global slot) so switching projects can't
// clobber another project's unsaved local draft — see setAutosaveProjectId.
const AUTOSAVE_KEY_PREFIX = 'hybridtm.studio.autosave.v1.'
function autosaveKey(projectId: string): string {
  return AUTOSAVE_KEY_PREFIX + projectId
}

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
  dataAssets: CanonicalDataAsset[]
  abuseCases: CanonicalAbuserStory[]
  selectedId: string | null
  selectedEdgeId: string | null
  selectedStoryId: string | null
  focusSubjectId: string | null
  findings: Finding[]
  storyCoverage: StoryCoverage[]
  lastSavedAt: string | null
  overlayMode: OverlayMode

  setNodes: (updater: (nodes: StudioNode[]) => StudioNode[]) => void
  setEdges: (updater: (edges: StudioEdge[]) => StudioEdge[]) => void
  select: (id: string | null) => void
  selectEdge: (id: string | null) => void
  selectStory: (id: string | null) => void
  setFocusSubject: (id: string | null) => void
  removeNode: (id: string) => void
  duplicateNode: (id: string) => void
  setTitle: (title: string) => void
  setOverlayMode: (mode: OverlayMode) => void
  addDataAsset: (name: string, classification?: string) => CanonicalDataAsset
  updateDataAsset: (id: string, patch: Partial<Pick<CanonicalDataAsset, 'name' | 'classification'>>) => void
  removeDataAsset: (id: string) => void
  addAbuseCase: (partial?: Partial<CanonicalAbuserStory>) => CanonicalAbuserStory
  updateAbuseCase: (title: string, patch: Partial<CanonicalAbuserStory>) => void
  removeAbuseCase: (title: string) => void

  addComponentFromKb: (kbId: string, kb: KbComponent, position: { x: number; y: number }) => void
  insertTemplate: (
    items: { kbId: string; kb: KbComponent; position: { x: number; y: number } }[],
    edges: { from: number; to: number }[],
  ) => void
  insertCanonicalModel: (model: CanonicalModel, layout: ModelLayout | undefined, anchor: { x: number; y: number }) => void
  addBoundary: (position: { x: number; y: number }) => void
  updateProperty: (nodeId: string, propertyId: string, value: PropertyValue) => void
  updateBoundary: (nodeId: string, patch: Partial<Pick<BoundaryNodeData, 'name' | 'boundaryType'>>) => void
  resizeBoundary: (nodeId: string, rect: { x: number; y: number; width: number; height: number }) => void
  updateEdgeProtocol: (edgeId: string, protocol: string) => void
  updateEdgeData: (edgeId: string, patch: Partial<DataFlowEdgeData>) => void
  connect: (sourceId: string, targetId: string) => void

  applyFindings: (findings: Finding[], storyCoverage?: StoryCoverage[]) => void
  toCanonicalModel: () => CanonicalModel
  toLayout: () => ModelLayout
  loadCanonicalModel: (model: CanonicalModel, layout?: ModelLayout | null) => void
  markSaved: (at: string) => void
}

type TemporalSlice = Pick<ModelState, 'title' | 'nodes' | 'edges'>

export const useModelStore = create<ModelState>()(
  temporal<ModelState, [], [], TemporalSlice>(
    (set, get) => ({
      title: 'Untitled model',
      nodes: [],
      edges: [],
      dataAssets: [],
      abuseCases: [],
      selectedId: null,
      selectedEdgeId: null,
      selectedStoryId: null,
      focusSubjectId: null,
      findings: [],
      storyCoverage: [],
      lastSavedAt: null,
      overlayMode: 'risks',

      setNodes: (updater) => set((s) => ({ nodes: updater(s.nodes) })),
      setEdges: (updater) => set((s) => ({ edges: updater(s.edges) })),
      // Selecting a node clears any edge selection and vice versa — the
      // Inspector shows one or the other, never both.
      select: (id) => set({ selectedId: id, selectedEdgeId: id ? null : get().selectedEdgeId, selectedStoryId: null }),
      selectEdge: (id) => set({ selectedEdgeId: id, selectedId: id ? null : get().selectedId, selectedStoryId: null }),
      selectStory: (id) => set({ selectedStoryId: id, selectedId: null, selectedEdgeId: null }),
      setFocusSubject: (id) => set({ focusSubjectId: id }),
      // Mirrors what xyflow's own Backspace/Delete key handling does
      // (applyNodeChanges with a "remove" change) — a boundary also drops
      // every node it contains, and any edge touching a removed node goes
      // with it, so the graph never ends up with a dangling parentId or an
      // edge pointing at a node that no longer exists.
      removeNode: (id) => {
        set((s) => {
          const toRemove = new Set([id, ...s.nodes.filter((n) => n.parentId === id).map((n) => n.id)])
          return {
            nodes: s.nodes.filter((n) => !toRemove.has(n.id)),
            edges: s.edges.filter((e) => !toRemove.has(e.source) && !toRemove.has(e.target)),
            selectedId: s.selectedId && toRemove.has(s.selectedId) ? null : s.selectedId,
          }
        })
      },
      // Component-only (a duplicated boundary with duplicated children would
      // need a whole id-remapping pass like insertTemplate's — not worth it
      // for a quick "clone this block" action) — clones properties/traits,
      // drops findings (they're keyed to the original node's id), and keeps
      // it in the same trust boundary as the original.
      duplicateNode: (id) => {
        const source = get().nodes.find((n) => n.id === id)
        if (!source || source.type !== 'component') return
        const offset = cascadeOffset(get().nodes.length)
        const clone: StudioNode = {
          ...source,
          id: freshId('component'),
          position: { x: source.position.x + offset.x + 24, y: source.position.y + offset.y + 24 },
          selected: false,
          data: { ...source.data, findingCount: 0, maxSeverity: undefined },
        }
        set((s) => ({ nodes: [...s.nodes, clone], selectedId: clone.id }))
      },
      setTitle: (title) => set({ title }),
      setOverlayMode: (overlayMode) => set({ overlayMode }),

      addDataAsset: (name, classification) => {
        const asset: CanonicalDataAsset = { id: freshId('asset'), name, classification }
        set((s) => ({ dataAssets: [...s.dataAssets, asset] }))
        return asset
      },

      updateDataAsset: (id, patch) => {
        set((s) => ({ dataAssets: s.dataAssets.map((a) => (a.id === id ? { ...a, ...patch } : a)) }))
      },

      removeDataAsset: (id) => {
        set((s) => ({
          dataAssets: s.dataAssets.filter((a) => a.id !== id),
          // An edge referencing a deleted asset would otherwise silently
          // point at nothing — strip it from every flow's dataSent/dataReceived.
          edges: s.edges.map((e) => ({
            ...e,
            data: {
              ...e.data,
              dataSent: e.data?.dataSent?.filter((aid) => aid !== id),
              dataReceived: e.data?.dataReceived?.filter((aid) => aid !== id),
            },
          })),
        }))
      },

      addAbuseCase: (partial) => {
        const title = partial?.title && /^[a-z][a-z0-9-]{0,62}$/.test(partial.title)
          ? partial.title
          : freshId('story')
        const story: CanonicalAbuserStory = {
          title,
          text: partial?.text ?? '',
          asA: partial?.asA ?? '',
          iWant: partial?.iWant ?? '',
          soThat: partial?.soThat ?? '',
          actorId: partial?.actorId ?? null,
          assetIds: partial?.assetIds ?? [],
          dataFlowIds: partial?.dataFlowIds ?? [],
          dataAssetIds: partial?.dataAssetIds ?? [],
          threatIds: partial?.threatIds ?? [],
          requiredCwes: partial?.requiredCwes ?? [],
          status: partial?.status ?? 'open',
        }
        set((s) => ({ abuseCases: [...s.abuseCases, story], selectedStoryId: story.title }))
        return story
      },

      updateAbuseCase: (title, patch) => {
        set((s) => ({
          abuseCases: s.abuseCases.map((c) => {
            if (c.title !== title) return c
            const next = { ...c, ...patch }
            if (patch.title && patch.title !== title) {
              // Keep selection in sync when renaming the story id.
              return next
            }
            return next
          }),
          selectedStoryId:
            get().selectedStoryId === title && patch.title && patch.title !== title
              ? patch.title
              : get().selectedStoryId,
        }))
      },

      removeAbuseCase: (title) => {
        set((s) => ({
          abuseCases: s.abuseCases.filter((c) => c.title !== title),
          selectedStoryId: s.selectedStoryId === title ? null : s.selectedStoryId,
        }))
      },

      addComponentFromKb: (kbId, kb, position) => {
        const node = buildComponentNode(kbId, kb, position)
        set((s) => ({ nodes: [...s.nodes, node] }))
      },

      insertTemplate: (items, edgeSpecs) => {
        const newNodes = items.map(({ kbId, kb, position }) => buildComponentNode(kbId, kb, position))
        const newEdges: StudioEdge[] = edgeSpecs.map(({ from, to }) => ({
          id: freshId('flow'),
          source: newNodes[from].id,
          target: newNodes[to].id,
          // ComponentNode has two named handles ("out" source, "in" target)
          // rather than one default of each — xyflow can't infer which to
          // use for a programmatically-created edge, so it silently fails
          // to render without these (found while verifying the gallery:
          // nodes appeared, edges didn't).
          sourceHandle: 'out',
          targetHandle: 'in',
          type: 'dataflow',
          data: {},
        }))
        set((s) => ({ nodes: [...s.nodes, ...newNodes], edges: [...s.edges, ...newEdges] }))
      },

      // Drops a full saved template (components/boundaries/flows + its own
      // data assets) onto the canvas as one atomic undo step. Every id —
      // node, edge, and data asset — gets a fresh one first: the same
      // template can be inserted more than once, or alongside content that
      // happens to reuse the same ids the template was authored with (it's
      // just a canonical model, built the same way any saved project is).
      insertCanonicalModel: (model, layout, anchor) => {
        const { nodes: rawNodes, edges: rawEdges } = canonicalModelToGraph(model, layout)
        const nodeIdMap = new Map(rawNodes.map((n) => [n.id, freshId('tpl')]))
        const assetIdMap = new Map((model.dataAssets ?? []).map((a) => [a.id, freshId('asset')]))
        const remapAssetIds = (ids?: string[]) => (ids ?? []).map((id) => assetIdMap.get(id) ?? id)

        const newNodes: StudioNode[] = rawNodes.map((n) => ({
          ...n,
          id: nodeIdMap.get(n.id)!,
          parentId: n.parentId ? nodeIdMap.get(n.parentId) : undefined,
          position: n.parentId ? n.position : { x: n.position.x + anchor.x, y: n.position.y + anchor.y },
        }))
        const newEdges: StudioEdge[] = rawEdges.map((e) => ({
          ...e,
          id: freshId('flow'),
          source: nodeIdMap.get(e.source) ?? e.source,
          target: nodeIdMap.get(e.target) ?? e.target,
          data: {
            ...e.data,
            dataSent: remapAssetIds(e.data?.dataSent),
            dataReceived: remapAssetIds(e.data?.dataReceived),
          },
        }))
        const newAssets: CanonicalDataAsset[] = (model.dataAssets ?? []).map((a) => ({
          ...a,
          id: assetIdMap.get(a.id)!,
        }))

        set((s) => ({
          nodes: [...s.nodes, ...newNodes],
          edges: [...s.edges, ...newEdges],
          dataAssets: [...s.dataAssets, ...newAssets],
        }))
      },

      addBoundary: (position) => {
        const id = freshId('boundary')
        const node: StudioNode = {
          id,
          type: 'boundary',
          position,
          style: { width: 420, height: 260 },
          zIndex: BOUNDARY_Z_INDEX,
          ariaLabel: 'Trust boundary, network cloud provider',
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

      updateBoundary: (nodeId, patch) => {
        set((s) => ({
          nodes: s.nodes.map((n) =>
            n.id === nodeId && n.data.kind === 'boundary' ? { ...n, data: { ...n.data, ...patch } } : n,
          ),
        }))
      },

      resizeBoundary: (nodeId, rect) => {
        set((s) => ({
          nodes: s.nodes.map((n) =>
            n.id === nodeId && n.data.kind === 'boundary'
              ? { ...n, position: { x: rect.x, y: rect.y }, style: { ...n.style, width: rect.width, height: rect.height } }
              : n,
          ),
        }))
      },

      updateEdgeProtocol: (edgeId, protocol) => {
        set((s) => ({
          edges: s.edges.map((e) => (e.id === edgeId ? { ...e, data: { ...e.data, protocol } } : e)),
        }))
      },

      updateEdgeData: (edgeId, patch) => {
        set((s) => ({
          edges: s.edges.map((e) => (e.id === edgeId ? { ...e, data: { ...e.data, ...patch } } : e)),
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

      applyFindings: (findings, storyCoverage = []) => {
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
          storyCoverage,
          nodes: s.nodes.map((n) => {
            if (n.data.kind !== 'component') return n
            const list = bySubject.get(`component:${n.id}`) ?? []
            const maxSeverity = list.length ? maxOf(list) : undefined
            const ariaLabel = list.length
              ? `${n.data.name} component, ${list.length} finding${list.length === 1 ? '' : 's'}, highest severity ${maxSeverity}`
              : `${n.data.name} component, no findings yet`
            return {
              ...n,
              ariaLabel,
              data: { ...n.data, findingCount: list.length, maxSeverity },
            }
          }),
          edges: s.edges.map((e) => {
            const list = bySubject.get(`flow:${e.id}`) ?? []
            return { ...e, data: { ...e.data, maxSeverity: list.length ? maxOf(list) : undefined } }
          }),
        }))
      },

      toCanonicalModel: () => {
        const { title, nodes, edges, dataAssets, abuseCases } = get()
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
          dataSent: e.data?.dataSent ?? [],
          dataReceived: e.data?.dataReceived ?? [],
          tags: e.data?.tags ?? [],
        }))

        return {
          schemaVersion: 1,
          model: { title, businessCriticality: 'important' },
          dataAssets,
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
          abuseCases,
        }
      },

      toLayout: () => {
        const { nodes } = get()
        const layoutNodes: Record<string, LayoutRect> = {}
        const groups: Record<string, LayoutGroup> = {}
        for (const n of nodes) {
          if (n.data.kind === 'component') {
            const abs = absolutePosition(n, nodes)
            layoutNodes[n.id] = { x: abs.x, y: abs.y, ...COMPONENT_LAYOUT_SIZE }
          } else if (n.data.kind === 'boundary') {
            const w = (n.style?.width as number) ?? DEFAULT_BOUNDARY_SIZE.w
            const h = (n.style?.height as number) ?? DEFAULT_BOUNDARY_SIZE.h
            groups[n.id] = { x: n.position.x, y: n.position.y, w, h, collapsed: false }
          }
        }
        return { schemaVersion: 1, nodes: layoutNodes, groups, edges: {}, viewport: { x: 0, y: 0, zoom: 1 } }
      },

      loadCanonicalModel: (model, layout) => {
        const { nodes, edges } = canonicalModelToGraph(model, layout)
        set({
          title: model.model.title,
          nodes,
          edges,
          dataAssets: model.dataAssets ?? [],
          abuseCases: model.abuseCases ?? [],
          selectedId: null,
          selectedEdgeId: null,
          selectedStoryId: null,
          findings: [],
          storyCoverage: [],
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

export function restoreAutosave(projectId: string): AutosavePayload | null {
  try {
    const raw = localStorage.getItem(autosaveKey(projectId))
    return raw ? (JSON.parse(raw) as AutosavePayload) : null
  } catch {
    return null
  }
}

export function clearAutosave(projectId: string): void {
  localStorage.removeItem(autosaveKey(projectId))
  useModelStore.setState({ lastSavedAt: null })
}

// Set by App.tsx whenever the open project changes, so the debounced writer
// below (which runs outside React, off a plain store subscription) knows
// which project's slot to write into. Skips saving entirely when null —
// e.g. during the moment loadCanonicalModel repopulates the canvas for a
// newly-switched project, before the effect that sets this has run.
let autosaveProjectId: string | null = null
export function setAutosaveProjectId(projectId: string | null): void {
  autosaveProjectId = projectId
}

let autosaveTimeout: ReturnType<typeof setTimeout> | undefined
useModelStore.subscribe((state, prevState) => {
  if (state.nodes === prevState.nodes && state.edges === prevState.edges && state.title === prevState.title) return
  if (!autosaveProjectId) return
  const projectId = autosaveProjectId
  if (autosaveTimeout) clearTimeout(autosaveTimeout)
  autosaveTimeout = setTimeout(() => {
    const { title, nodes, edges } = useModelStore.getState()
    const savedAt = new Date().toISOString()
    const payload: AutosavePayload = { title, nodes, edges, savedAt }
    localStorage.setItem(autosaveKey(projectId), JSON.stringify(payload))
    useModelStore.getState().markSaved(savedAt)
  }, 800)
})

/** Keyboard-add (palette Enter/Space) and the command palette both drop new
 * nodes at the same viewport-center point — without this, repeated
 * additions would stack exactly on top of each other. Cascades in an
 * 8-step diagonal and wraps, rather than growing unbounded. */
export function cascadeOffset(nodeCount: number): { x: number; y: number } {
  const step = 28
  const i = nodeCount % 8
  return { x: i * step, y: i * step }
}
