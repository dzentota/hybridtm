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

export interface ModelVersionSummary {
  id: string
  project: string
  data: CanonicalModel
}

export function createModelVersion(projectIri: string, data: CanonicalModel): Promise<ModelVersionSummary> {
  return request<ModelVersionSummary>('/api/model_versions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/ld+json' },
    body: JSON.stringify({ project: projectIri, schemaVersion: 1, data }),
  })
}

export function analyze(modelVersionId: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/model-versions/${modelVersionId}/analyze`, { method: 'POST' })
}

export { ApiError }
