import type { AnalysisResult, CanonicalModel, KbBundle, ModelLayout } from './types'

const TOKEN_KEY = 'hybridtm.studio.token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token === null) localStorage.removeItem(TOKEN_KEY)
  else localStorage.setItem(TOKEN_KEY, token)
}

/** Clears the token and fires the same event the 401 handler below uses to
 * bounce back to the login screen — one path for "no longer authed",
 * whether that's the user's choice or the server's. */
export function logout(): void {
  setToken(null)
  window.dispatchEvent(new Event('hybridtm:unauthorized'))
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
      // API Platform's standard problem-details error shape uses `detail`
      // (e.g. "Access Denied."), not `error`/`message` — those were never
      // populated by this backend, so failures always showed the generic
      // res.statusText ("Forbidden") instead of the real reason.
      message = body.detail ?? body.error ?? body.message ?? message
    } catch {
      // no JSON body
    }
    // A previously-valid token can go stale (expiry, server restart, revoked
    // session) at any point during a session, not just at initial load — the
    // rest of the app (App.tsx) treats "token present" as "authed" and never
    // re-checks, so without this every panel just hangs on its loading state
    // forever once the token dies. Clearing it and telling App.tsx to drop
    // back to the login screen turns that silent hang into a re-login prompt.
    if (res.status === 401 && token) {
      setToken(null)
      window.dispatchEvent(new Event('hybridtm:unauthorized'))
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
  layout?: ModelLayout | null
  createdAt?: string
  status?: string
}

export function createModelVersion(
  projectIri: string,
  data: CanonicalModel,
  layout?: ModelLayout,
): Promise<ModelVersionSummary> {
  return request<ModelVersionSummary>('/api/model_versions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/ld+json' },
    body: JSON.stringify({ project: projectIri, schemaVersion: 1, data, layout }),
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

export interface ModelTemplateSummary {
  id: string
  name: string
  description?: string | null
  data: CanonicalModel
  layout?: ModelLayout | null
  createdAt?: string
}

// User-saved templates (distinct from the KB's own `Kind::Template` entries
// and from Studio's hardcoded STARTER_TEMPLATES) — "save my current canvas
// for reuse" (§ save-as-template).
export function listModelTemplates(): Promise<ModelTemplateSummary[]> {
  return request<ModelTemplateSummary[]>('/api/model_templates')
}

export function createModelTemplate(
  name: string,
  description: string,
  data: CanonicalModel,
  layout?: ModelLayout,
): Promise<ModelTemplateSummary> {
  return request<ModelTemplateSummary>('/api/model_templates', {
    method: 'POST',
    headers: { 'Content-Type': 'application/ld+json' },
    body: JSON.stringify({ name, description, data, layout }),
  })
}

export function deleteModelTemplate(id: string): Promise<void> {
  return request<void>(`/api/model_templates/${id}`, { method: 'DELETE' })
}

export { ApiError }
