import { useState } from 'react'
import Editor from '@monaco-editor/react'
import { createModelVersion, exportModelAsPhp, getModelVersion, importPhp } from '../api/client'
import { useModelStore } from '../store/model.store'
import { useProjectStore, projectIri } from '../project/project.store'
import { useElkLayout } from '../layout/useElkLayout'

/** Split-view PHP DSL preview + two-way sync (T-7.15). Sync happens on
 * explicit Refresh/Apply, not per-keystroke: the export/import round trip
 * goes through real persisted ModelVersions (there's no stateless
 * "convert this JSON" endpoint), so treating every keystroke as a save
 * would spam the version history and add network latency to typing. */
export function PhpSyncPanel() {
  const [code, setCode] = useState('')
  const [warnings, setWarnings] = useState<string[]>([])
  const [busy, setBusy] = useState<'refresh' | 'apply' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const toCanonicalModel = useModelStore((s) => s.toCanonicalModel)
  const toLayout = useModelStore((s) => s.toLayout)
  const loadCanonicalModel = useModelStore((s) => s.loadCanonicalModel)
  const currentProjectId = useProjectStore((s) => s.currentProjectId)
  const { runLayout } = useElkLayout()

  const refresh = async () => {
    if (!currentProjectId) return
    setBusy('refresh')
    setError(null)
    try {
      const modelVersion = await createModelVersion(projectIri(currentProjectId), toCanonicalModel(), toLayout())
      const php = await exportModelAsPhp(modelVersion.id)
      setCode(php)
      setWarnings([])
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const apply = async () => {
    if (!currentProjectId) return
    setBusy('apply')
    setError(null)
    try {
      const result = await importPhp(currentProjectId, code)
      setWarnings(result.warnings)
      const modelVersion = await getModelVersion(result.id)
      loadCanonicalModel(modelVersion.data, modelVersion.layout)
      // ImportController never persists a `layout` alongside a PHP-DSL
      // import (there's no canvas position info in the DSL to carry over),
      // so this always lands on canonicalModelToGraph's fallback grid — a
      // reasonable default, but not as good as letting ELK actually pack
      // boundaries/components without overlap. Skip it if the reader
      // returned an actual saved layout (defensive; not expected today).
      if (!modelVersion.layout) await runLayout()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="flex flex-col h-full min-h-0" style={{ borderLeft: '1px solid var(--border)' }}>
      <div className="px-2 py-1.5 flex items-center gap-2 text-sm" style={{ borderBottom: '1px solid var(--border)' }}>
        <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
          threat-model.php
        </span>
        <button
          type="button"
          disabled={busy !== null || !currentProjectId}
          onClick={() => void refresh()}
          className="px-2 py-0.5 rounded text-xs disabled:opacity-40"
          style={{ border: '1px solid var(--border)' }}
        >
          {busy === 'refresh' ? 'Refreshing…' : 'Refresh from canvas'}
        </button>
        <button
          type="button"
          disabled={busy !== null || code === ''}
          onClick={() => void apply()}
          className="px-2 py-0.5 rounded text-xs disabled:opacity-40"
          style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
        >
          {busy === 'apply' ? 'Applying…' : 'Apply to canvas'}
        </button>
      </div>
      {error && (
        <div className="px-2 py-1 text-xs" style={{ background: 'var(--severity-critical)', color: 'white' }}>
          {error}
        </div>
      )}
      {warnings.length > 0 && (
        <div
          className="px-2 py-1.5 text-xs flex flex-col gap-0.5"
          style={{ background: 'color-mix(in srgb, var(--severity-medium) 20%, var(--surface-0))', borderBottom: '1px solid var(--border)' }}
          role="alert"
        >
          <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
            Non-canonical constructs (kept, but not represented on the canvas):
          </span>
          {warnings.map((w) => (
            <span key={w} style={{ color: 'var(--text-primary)' }}>
              {w}
            </span>
          ))}
        </div>
      )}
      <div className="flex-1 min-h-0">
        {code === '' ? (
          <div className="p-4 text-sm" style={{ color: 'var(--text-secondary)' }}>
            Click "Refresh from canvas" to generate the PHP DSL for the current model.
          </div>
        ) : (
          <Editor
            language="php"
            value={code}
            onChange={(value) => setCode(value ?? '')}
            theme="vs-dark"
            options={{ minimap: { enabled: false }, fontSize: 12 }}
          />
        )}
      </div>
    </div>
  )
}
