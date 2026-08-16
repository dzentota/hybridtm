import { useEffect, useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { analyze, createModelVersion, createProject, getKbBundle, getToken, listProjects } from './api/client'
import { useModelStore, useTemporalStore, restoreAutosave, clearAutosave } from './store/model.store'
import { FlowCanvas } from './canvas/FlowCanvas'
import { ComponentPalette } from './palette/ComponentPalette'
import { Inspector } from './inspector/Inspector'
import { FindingsPanel } from './findings/FindingsPanel'
import { LoginScreen } from './auth/LoginScreen'
import { Toolbar } from './toolbar/Toolbar'

const DEMO_PROJECT_SLUG = 'studio-demo'

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

function AutosaveRestorePrompt() {
  const [pending] = useState(() => restoreAutosave())
  const [dismissed, setDismissed] = useState(false)

  if (!pending || dismissed) return null

  return (
    <div
      className="absolute top-14 left-1/2 -translate-x-1/2 z-10 px-3 py-2 rounded shadow text-sm flex items-center gap-3"
      style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
      role="alertdialog"
      aria-label="Restore autosaved model"
    >
      <span>Unsaved changes from a previous session were found (saved {new Date(pending.savedAt).toLocaleTimeString()}).</span>
      <button
        className="px-2 py-1 rounded font-medium"
        style={{ background: 'var(--accent)', color: 'white' }}
        onClick={() => {
          useModelStore.setState({ title: pending.title, nodes: pending.nodes, edges: pending.edges })
          setDismissed(true)
        }}
      >
        Restore
      </button>
      <button
        className="px-2 py-1 rounded"
        style={{ border: '1px solid var(--border)' }}
        onClick={() => {
          clearAutosave()
          setDismissed(true)
        }}
      >
        Discard
      </button>
    </div>
  )
}

function Studio() {
  const { data: kb } = useQuery({ queryKey: ['kb-bundle'], queryFn: getKbBundle })
  const toCanonicalModel = useModelStore((s) => s.toCanonicalModel)
  const applyFindings = useModelStore((s) => s.applyFindings)
  useUndoRedoHotkeys()

  const runAnalysis = useMutation({
    mutationFn: async () => {
      const projects = await listProjects()
      const project =
        projects.find((p) => p.slug === DEMO_PROJECT_SLUG) ?? (await createProject(DEMO_PROJECT_SLUG, 'Studio demo'))
      const modelVersion = await createModelVersion(`/api/threat_model_projects/${project.id}`, toCanonicalModel())
      return analyze(modelVersion.id)
    },
    onSuccess: (result) => applyFindings(result.findings),
  })

  return (
    <div className="w-full h-full grid relative" style={{ gridTemplateColumns: '260px 1fr 320px', gridTemplateRows: '1fr' }}>
      <AutosaveRestorePrompt />
      <ComponentPalette kb={kb} />
      <div className="flex flex-col h-full min-w-0">
        <Toolbar kb={kb} />
        <div className="flex-1 min-h-0">
          <FlowCanvas kb={kb} />
        </div>
      </div>
      <div className="grid h-full min-h-0" style={{ gridTemplateRows: '1fr 1fr' }}>
        <div style={{ borderBottom: '1px solid var(--border)' }} className="min-h-0 overflow-hidden">
          <Inspector kb={kb} />
        </div>
        <div className="min-h-0 overflow-hidden">
          <FindingsPanel onRunAnalysis={() => runAnalysis.mutate()} isAnalyzing={runAnalysis.isPending} />
        </div>
      </div>
    </div>
  )
}

function App() {
  const [authed, setAuthed] = useState(() => getToken() !== null)

  if (!authed) {
    return <LoginScreen onLoggedIn={() => setAuthed(true)} />
  }

  return <Studio />
}

export default App
