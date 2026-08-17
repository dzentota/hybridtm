import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ReactFlowProvider } from '@xyflow/react'
import {
  analyze,
  createModelVersion,
  createProject,
  getKbBundle,
  getToken,
  listModelVersions,
  listProjects,
  type ModelVersionSummary,
} from './api/client'
import type { CanonicalModel } from './api/types'
import {
  useModelStore,
  useTemporalStore,
  restoreAutosave,
  clearAutosave,
  setAutosaveProjectId,
  setKbIconIndex,
} from './store/model.store'
import { useProjectStore, projectIri } from './project/project.store'
import { FlowCanvas } from './canvas/FlowCanvas'
import { ComponentPalette } from './palette/ComponentPalette'
import { Inspector } from './inspector/Inspector'
import { FindingsPanel } from './findings/FindingsPanel'
import { LoginScreen } from './auth/LoginScreen'
import { Toolbar } from './toolbar/Toolbar'
import { CommandPalette } from './command/CommandPalette'
import { TemplateGallery } from './templates/TemplateGallery'
import { DiffView } from './diff/DiffView'
import { PhpSyncPanel } from './phpsync/PhpSyncPanel'

const EMPTY_CANONICAL_MODEL: CanonicalModel = {
  schemaVersion: 1,
  model: { title: 'Untitled model' },
  dataAssets: [],
  components: [],
  trustBoundaries: [],
  dataFlows: [],
}

function useUndoRedoHotkeys() {
  const { undo, redo } = useTemporalStore()
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey
      if (!meta || e.key.toLowerCase() !== 'z') return
      const target = e.target as HTMLElement | null
      if (target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return
      e.preventDefault()
      if (e.shiftKey) redo()
      else undo()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [undo, redo])
}

/** Offers to restore a locally-autosaved draft on top of whatever just
 * loaded for the current project — re-checked on every project switch
 * (keyed by projectId) rather than once at mount, since autosave is now
 * per-project (see setAutosaveProjectId). */
function AutosaveRestorePrompt({ projectId }: { projectId: string | null }) {
  const { t } = useTranslation()
  const [pending, setPending] = useState<ReturnType<typeof restoreAutosave>>(null)
  const [dismissedFor, setDismissedFor] = useState<string | null>(null)

  useEffect(() => {
    setPending(projectId ? restoreAutosave(projectId) : null)
  }, [projectId])

  if (!pending || !projectId || dismissedFor === projectId) return null

  return (
    <div
      className="absolute top-14 left-1/2 -translate-x-1/2 z-10 px-3 py-2 rounded shadow text-sm flex items-center gap-3"
      style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
      role="alertdialog"
      aria-label="Restore autosaved model"
    >
      <span>{t('autosave.found', { time: new Date(pending.savedAt).toLocaleTimeString() })}</span>
      <button
        className="px-2 py-1 rounded font-medium"
        style={{ background: 'var(--accent)', color: 'white' }}
        onClick={() => {
          useModelStore.setState({ title: pending.title, nodes: pending.nodes, edges: pending.edges })
          setDismissedFor(projectId)
        }}
      >
        {t('autosave.restore')}
      </button>
      <button
        className="px-2 py-1 rounded"
        style={{ border: '1px solid var(--border)' }}
        onClick={() => {
          clearAutosave(projectId)
          setDismissedFor(projectId)
        }}
      >
        {t('autosave.discard')}
      </button>
    </div>
  )
}

function CollapsedPanelStrip({ label, chevron, onClick }: { label: string; chevron: string; onClick: () => void }) {
  return (
    <div
      className="h-full flex flex-col items-center pt-2"
      style={{ background: 'var(--surface-1)', borderInline: '1px solid var(--border)' }}
    >
      <button
        type="button"
        aria-label={label}
        title={label}
        onClick={onClick}
        className="w-6 h-8 rounded flex items-center justify-center text-sm"
        style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
      >
        {chevron}
      </button>
    </div>
  )
}

const PANEL_COLLAPSE_KEY = 'hybridtm.studio.panels.v1'
const COLLAPSED_PANEL_WIDTH = 40

function loadPanelCollapse(): { left: boolean; right: boolean } {
  try {
    const raw = localStorage.getItem(PANEL_COLLAPSE_KEY)
    if (!raw) return { left: false, right: false }
    const parsed = JSON.parse(raw)
    return { left: !!parsed.left, right: !!parsed.right }
  } catch {
    return { left: false, right: false }
  }
}

function Studio() {
  const queryClient = useQueryClient()
  const { data: kb } = useQuery({ queryKey: ['kb-bundle'], queryFn: getKbBundle })
  useEffect(() => {
    if (kb) setKbIconIndex(kb.components)
  }, [kb])

  const { data: projects } = useQuery({ queryKey: ['projects'], queryFn: listProjects })
  const { data: modelVersions } = useQuery({ queryKey: ['model-versions'], queryFn: listModelVersions })
  const currentProjectId = useProjectStore((s) => s.currentProjectId)
  const setCurrentProjectId = useProjectStore((s) => s.setCurrentProjectId)
  const loadCanonicalModel = useModelStore((s) => s.loadCanonicalModel)

  /** Switches the open project: points autosave at its slot and loads its
   * latest saved ModelVersion into the canvas (or a blank model if it has
   * none yet). Only ever called explicitly — from the picker, "new
   * project", or the one-time initial pick below — never reactively off
   * query refetches, so an unrelated cache invalidation (e.g. after Run
   * analysis) can't suddenly overwrite in-progress edits. */
  const switchProject = (id: string, versions: ModelVersionSummary[]) => {
    setCurrentProjectId(id)
    setAutosaveProjectId(id)
    const iri = projectIri(id)
    const latest = versions.find((v) => v.project === iri)
    loadCanonicalModel(latest ? latest.data : EMPTY_CANONICAL_MODEL, latest?.layout)
  }

  // Bootstrap: a brand-new tenant has zero projects — seed one so the
  // canvas isn't a dead end with nothing to select.
  const bootstrappedRef = useRef(false)
  useEffect(() => {
    if (bootstrappedRef.current || !projects || projects.length > 0) return
    bootstrappedRef.current = true
    void createProject('studio-demo', 'Studio demo').then(() => {
      void queryClient.invalidateQueries({ queryKey: ['projects'] })
    })
  }, [projects, queryClient])

  // Pick an initial project exactly once: the persisted currentProjectId if
  // it still exists, else the most recently created one.
  const initializedRef = useRef(false)
  useEffect(() => {
    if (initializedRef.current || !projects || projects.length === 0 || modelVersions === undefined) return
    initializedRef.current = true
    const initialId = currentProjectId && projects.some((p) => p.id === currentProjectId) ? currentProjectId : projects[0].id
    switchProject(initialId, modelVersions)
  }, [projects, modelVersions]) // eslint-disable-line react-hooks/exhaustive-deps

  const toCanonicalModel = useModelStore((s) => s.toCanonicalModel)
  const toLayout = useModelStore((s) => s.toLayout)
  const applyFindings = useModelStore((s) => s.applyFindings)
  const [templatesOpen, setTemplatesOpen] = useState(false)
  const [diffOpen, setDiffOpen] = useState(false)
  const [codeOpen, setCodeOpen] = useState(false)
  const [{ left: leftCollapsed, right: rightCollapsed }, setPanelCollapse] = useState(loadPanelCollapse)
  useEffect(() => {
    localStorage.setItem(PANEL_COLLAPSE_KEY, JSON.stringify({ left: leftCollapsed, right: rightCollapsed }))
  }, [leftCollapsed, rightCollapsed])
  const toggleLeftPanel = () => setPanelCollapse((s) => ({ ...s, left: !s.left }))
  const toggleRightPanel = () => setPanelCollapse((s) => ({ ...s, right: !s.right }))
  useUndoRedoHotkeys()

  const runAnalysis = useMutation({
    mutationFn: async () => {
      if (!currentProjectId) throw new Error('No project selected')
      const modelVersion = await createModelVersion(projectIri(currentProjectId), toCanonicalModel(), toLayout())
      void queryClient.invalidateQueries({ queryKey: ['model-versions'] })
      return analyze(modelVersion.id)
    },
    onSuccess: (result) => applyFindings(result.findings),
  })

  const createProjectMutation = useMutation({
    mutationFn: (vars: { slug: string; title: string }) => createProject(vars.slug, vars.title),
    onSuccess: (project) => {
      void queryClient.invalidateQueries({ queryKey: ['projects'] })
      switchProject(project.id, modelVersions ?? [])
    },
  })

  // Explicit save, distinct from "Run analysis": persists a ModelVersion
  // without also running (and waiting on) the analyzer — there was
  // previously no way to save a draft without triggering analysis.
  const saveModel = useMutation({
    mutationFn: async () => {
      if (!currentProjectId) throw new Error('No project selected')
      return createModelVersion(projectIri(currentProjectId), toCanonicalModel(), toLayout())
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['model-versions'] })
      useModelStore.getState().markSaved(new Date().toISOString())
    },
  })

  return (
    <div
      className="w-full h-full grid relative overflow-auto"
      style={{
        gridTemplateColumns: [
          leftCollapsed ? `${COLLAPSED_PANEL_WIDTH}px` : 'minmax(220px, 260px)',
          'minmax(420px, 1fr)',
          rightCollapsed ? `${COLLAPSED_PANEL_WIDTH}px` : 'minmax(280px, 320px)',
        ].join(' '),
        gridTemplateRows: '1fr',
      }}
    >
      <AutosaveRestorePrompt projectId={currentProjectId} />
      <CommandPalette
        kb={kb}
        onRunAnalysis={() => runAnalysis.mutate()}
        onOpenTemplates={() => setTemplatesOpen(true)}
        onOpenDiff={() => setDiffOpen(true)}
        onToggleCode={() => setCodeOpen((v) => !v)}
        onToggleLeftPanel={toggleLeftPanel}
        onToggleRightPanel={toggleRightPanel}
      />
      <TemplateGallery kb={kb} open={templatesOpen} onClose={() => setTemplatesOpen(false)} />
      <DiffView open={diffOpen} onClose={() => setDiffOpen(false)} />
      {leftCollapsed ? (
        <CollapsedPanelStrip label="Expand component palette" onClick={toggleLeftPanel} chevron="›" />
      ) : (
        <ComponentPalette kb={kb} onCollapse={toggleLeftPanel} />
      )}
      <div className="relative h-full min-h-0 min-w-0">
        <div className="absolute inset-x-3 top-3 z-10">
          <Toolbar
            kb={kb}
            projects={projects ?? []}
            currentProjectId={currentProjectId}
            onSwitchProject={(id) => switchProject(id, modelVersions ?? [])}
            onCreateProject={(slug, title) => createProjectMutation.mutate({ slug, title })}
            onSave={() => saveModel.mutate()}
            isSaving={saveModel.isPending}
            saveError={saveModel.isError ? (saveModel.error instanceof Error ? saveModel.error.message : String(saveModel.error)) : null}
            onOpenTemplates={() => setTemplatesOpen(true)}
            onOpenDiff={() => setDiffOpen(true)}
            onToggleCode={() => setCodeOpen((v) => !v)}
          />
        </div>
        <div className="h-full min-h-0 grid" style={{ gridTemplateColumns: codeOpen ? '1fr 1fr' : '1fr' }}>
          <FlowCanvas kb={kb} />
          {codeOpen && <PhpSyncPanel />}
        </div>
      </div>
      {rightCollapsed ? (
        <CollapsedPanelStrip label="Expand inspector and findings" onClick={toggleRightPanel} chevron="‹" />
      ) : (
        <div className="relative grid h-full min-h-0" style={{ gridTemplateRows: '1fr 1fr' }}>
          <button
            type="button"
            aria-label="Collapse inspector and findings panel"
            title="Collapse panel"
            onClick={toggleRightPanel}
            className="absolute -left-3 top-1/2 -translate-y-1/2 z-10 w-6 h-10 rounded flex items-center justify-center text-sm"
            style={{ background: 'var(--surface-0)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
          >
            ›
          </button>
          <div style={{ borderBottom: '1px solid var(--border)', borderLeft: '1px solid var(--border)' }} className="min-h-0 overflow-hidden">
            <Inspector kb={kb} />
          </div>
          <div className="min-h-0 overflow-hidden">
            <FindingsPanel
              kb={kb}
              onRunAnalysis={() => runAnalysis.mutate()}
              isAnalyzing={runAnalysis.isPending}
              analysisError={
                runAnalysis.isError ? (runAnalysis.error instanceof Error ? runAnalysis.error.message : String(runAnalysis.error)) : null
              }
            />
          </div>
        </div>
      )}
    </div>
  )
}

function App() {
  const [authed, setAuthed] = useState(() => getToken() !== null)

  useEffect(() => {
    const onUnauthorized = () => setAuthed(false)
    window.addEventListener('hybridtm:unauthorized', onUnauthorized)
    return () => window.removeEventListener('hybridtm:unauthorized', onUnauthorized)
  }, [])

  if (!authed) {
    return <LoginScreen onLoggedIn={() => setAuthed(true)} />
  }

  return (
    <ReactFlowProvider>
      <Studio />
    </ReactFlowProvider>
  )
}

export default App
