import { create } from 'zustand'

const CURRENT_PROJECT_KEY = 'hybridtm.studio.currentProjectId'

interface ProjectState {
  currentProjectId: string | null
  setCurrentProjectId: (id: string) => void
}

/** Which project's canvas is currently open. A standalone store (not part of
 * model.store.ts) so PhpSyncPanel can read the current project without prop
 * drilling from App.tsx, and so switching projects is decoupled from the
 * canvas state itself. */
export const useProjectStore = create<ProjectState>((set) => ({
  currentProjectId: localStorage.getItem(CURRENT_PROJECT_KEY),
  setCurrentProjectId: (id) => {
    localStorage.setItem(CURRENT_PROJECT_KEY, id)
    set({ currentProjectId: id })
  },
}))

export function projectIri(id: string): string {
  return `/api/threat_model_projects/${id}`
}
