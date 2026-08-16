import type { AnalysisResult, CanonicalModel, KbBundle } from './types'

const TOKEN_KEY = 'hybridtm.studio.token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token === null) localStorage.removeItem(TOKEN_KEY)
  else localStorage.setItem(TOKEN_KEY, token)
}

class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  if (token) headers.set('Authorization', `Bearer ${token}`)

  const res = await fetch(path, { ...init, headers })
  if (!res.ok) {
    let message = res.statusText
    try {
      const body = await res.json()
      message = body.error ?? body.message ?? message
    } catch {
      // no JSON body
    }
    throw new ApiError(res.status, message)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export async function login(email: string, password: string): Promise<string> {
  const { token } = await request<{ token: string }>('/login_check', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
  setToken(token)
  return token
}

export function getKbBundle(): Promise<KbBundle> {
  return request<KbBundle>('/kb/bundle')
}

export interface ProjectSummary {
  id: string
  slug: string
  title: string
}

export function listProjects(): Promise<ProjectSummary[]> {
  // Plain `Accept: application/json` gets API Platform's bare-array format,
  // not the Hydra `{member: [...]}` collection shape.
  return request<ProjectSummary[]>('/api/threat_model_projects')
}

export function createProject(slug: string, title: string): Promise<ProjectSummary> {
  return request<ProjectSummary>('/api/threat_model_projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/ld+json' },
    body: JSON.stringify({ slug, title }),
  })
}

export const DEMO_PROJECT_SLUG = 'studio-demo'

// Shared find-or-create used by every feature that needs a project to save
// against (run analysis, PHP sync, ...) — one place to fix if/when the demo
// project flow changes.
export async function ensureDemoProject(): Promise<ProjectSummary> {
  const projects = await listProjects()
  return projects.find((p) => p.slug === DEMO_PROJECT_SLUG) ?? createProject(DEMO_PROJECT_SLUG, 'Studio demo')
}

export interface ModelVersionSummary {
  id: string
  project: string
  data: CanonicalModel
  createdAt?: string
  status?: string
}

export function createModelVersion(projectIri: string, data: CanonicalModel): Promise<ModelVersionSummary> {
  return request<ModelVersionSummary>('/api/model_versions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/ld+json' },
    body: JSON.stringify({ project: projectIri, schemaVersion: 1, data }),
  })
}

// No `project` ApiFilter is declared server-side, so this returns every
// version this tenant's RLS makes visible — fine for the single demo
// project Studio currently works against; the diff view (T-7.22) filters
// client-side by project IRI.
export function listModelVersions(): Promise<ModelVersionSummary[]> {
  return request<ModelVersionSummary[]>('/api/model_versions')
}

export function getModelVersion(id: string): Promise<ModelVersionSummary> {
  return request<ModelVersionSummary>(`/api/model_versions/${id}`)
}

export function analyze(modelVersionId: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/model-versions/${modelVersionId}/analyze`, { method: 'POST' })
}

// Not JSON (Content-Type: text/x-php) — can't go through request()'s res.json().
export async function exportModelAsPhp(modelVersionId: string): Promise<string> {
  const token = getToken()
  const headers = new Headers()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const res = await fetch(`/model-versions/${modelVersionId}/export/php`, { headers })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return res.text()
}

export interface ImportResult {
  id: string
  warnings: string[]
}

export function importPhp(projectId: string, code: string): Promise<ImportResult> {
  return request<ImportResult>(`/threat-model-projects/${projectId}/import/php`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/x-php' },
    body: code,
  })
}

export { ApiError }
