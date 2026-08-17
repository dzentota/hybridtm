import { useState } from 'react'
import type { ProjectSummary } from '../api/client'

function slugify(title: string): string {
  const base =
    title
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'project'
  const prefixed = /^[a-z]/.test(base) ? base : `p-${base}`
  // A short random suffix sidesteps needing to check for slug collisions
  // up front — two projects titled the same no longer 500 on create.
  const suffix = Math.random().toString(36).slice(2, 6)
  return `${prefixed}-${suffix}`.slice(0, 80)
}

/** Project picker (simple v1): a native <select> over every project the
 * caller's tenant can see, plus inline "new project" entry — no separate
 * project-management screen yet. Switching projects reloads the canvas from
 * that project's latest saved ModelVersion (App.tsx owns that logic; this
 * component only picks the id/title). */
export function ProjectSwitcher({
  projects,
  currentProjectId,
  onSwitch,
  onCreate,
}: {
  projects: ProjectSummary[]
  currentProjectId: string | null
  onSwitch: (id: string) => void
  onCreate: (slug: string, title: string) => void
}) {
  const [creating, setCreating] = useState(false)
  const [newTitle, setNewTitle] = useState('')

  if (creating) {
    return (
      <form
        className="flex items-center gap-1"
        onSubmit={(e) => {
          e.preventDefault()
          const title = newTitle.trim()
          if (!title) return
          onCreate(slugify(title), title)
          setNewTitle('')
          setCreating(false)
        }}
      >
        <input
          autoFocus
          value={newTitle}
          onChange={(e) => setNewTitle(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setCreating(false)
          }}
          placeholder="New project name"
          aria-label="New project name"
          className="px-1.5 py-1 rounded text-sm"
          style={{ border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)', width: '160px' }}
        />
        <button type="submit" className="px-2 py-1 rounded text-sm" style={{ border: '1px solid var(--border)' }}>
          Create
        </button>
        <button
          type="button"
          aria-label="Cancel new project"
          onClick={() => setCreating(false)}
          className="px-2 py-1 rounded text-sm"
          style={{ border: '1px solid var(--border)' }}
        >
          ✕
        </button>
      </form>
    )
  }

  return (
    <label className="flex items-center gap-1.5">
      <span style={{ color: 'var(--text-secondary)' }}>Project:</span>
      <select
        aria-label="Current project"
        value={currentProjectId ?? ''}
        onChange={(e) => onSwitch(e.target.value)}
        className="px-1.5 py-1 rounded text-sm"
        style={{ border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }}
      >
        {projects.map((p) => (
          <option key={p.id} value={p.id}>
            {p.title}
          </option>
        ))}
      </select>
      <button
        type="button"
        aria-label="New project"
        title="New project"
        onClick={() => setCreating(true)}
        className="px-2 py-1 rounded text-sm"
        style={{ border: '1px solid var(--border)' }}
      >
        +
      </button>
    </label>
  )
}
