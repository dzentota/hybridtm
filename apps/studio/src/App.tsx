import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { analyze, createModelVersion, createProject, getKbBundle, getToken, listProjects } from './api/client'
import { useModelStore } from './store/model.store'
import { FlowCanvas } from './canvas/FlowCanvas'
import { ComponentPalette } from './palette/ComponentPalette'
import { Inspector } from './inspector/Inspector'
import { FindingsPanel } from './findings/FindingsPanel'
import { LoginScreen } from './auth/LoginScreen'

const DEMO_PROJECT_SLUG = 'studio-demo'

function Studio() {
  const { data: kb } = useQuery({ queryKey: ['kb-bundle'], queryFn: getKbBundle })
  const toCanonicalModel = useModelStore((s) => s.toCanonicalModel)
  const applyFindings = useModelStore((s) => s.applyFindings)

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
    <div className="w-full h-full grid" style={{ gridTemplateColumns: '260px 1fr 320px' }}>
      <ComponentPalette kb={kb} />
      <div className="flex flex-col h-full min-w-0">
        <div className="px-3 py-2 text-sm font-medium" style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-primary)' }}>
          HybridTM Studio — drag a component from the palette onto the canvas
        </div>
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
