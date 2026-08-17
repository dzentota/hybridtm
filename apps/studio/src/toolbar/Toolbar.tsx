import { useEffect, useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import { useTranslation } from 'react-i18next'
import { useModelStore, useTemporalStore, type OverlayMode } from '../store/model.store'
import { useElkLayout } from '../layout/useElkLayout'
import { useExportCanvas } from '../canvas/useExportCanvas'
import { ProjectSwitcher } from './ProjectSwitcher'
import { logout, type ProjectSummary } from '../api/client'
import type { KbBundle } from '../api/types'

const OVERLAY_KEYS: Record<OverlayMode, string> = {
  risks: 'toolbar.overlayRisks',
  data: 'toolbar.overlayData',
  exposure: 'toolbar.overlayExposure',
  coverage: 'toolbar.overlayCoverage',
}

function SavedIndicator() {
  const { t } = useTranslation()
  const lastSavedAt = useModelStore((s) => s.lastSavedAt)
  const [, forceTick] = useState(0)

  useEffect(() => {
    const id = setInterval(() => forceTick((n) => n + 1), 15_000)
    return () => clearInterval(id)
  }, [])

  if (!lastSavedAt) return <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{t('toolbar.notSaved')}</span>

  const seconds = Math.max(0, Math.round((Date.now() - new Date(lastSavedAt).getTime()) / 1000))
  const label =
    seconds < 5
      ? t('toolbar.savedNow')
      : seconds < 60
        ? t('toolbar.savedSecondsAgo', { count: seconds })
        : t('toolbar.savedMinutesAgo', { count: Math.round(seconds / 60) })
  return (
    <span className="text-xs" style={{ color: 'var(--text-secondary)' }} aria-live="polite">
      {label}
    </span>
  )
}

export function Toolbar({
  kb: _kb,
  projects,
  currentProjectId,
  onSwitchProject,
  onCreateProject,
  onSave,
  isSaving,
  saveError,
  onOpenTemplates,
  onOpenDiff,
  onToggleCode,
}: {
  kb: KbBundle | undefined
  projects: ProjectSummary[]
  currentProjectId: string | null
  onSwitchProject: (id: string) => void
  onCreateProject: (slug: string, title: string) => void
  onSave: () => void
  isSaving: boolean
  saveError: string | null
  onOpenTemplates: () => void
  onOpenDiff: () => void
  onToggleCode: () => void
}) {
  const { t, i18n } = useTranslation()
  const { undo, redo, canUndo, canRedo } = useTemporalStore()
  const title = useModelStore((s) => s.title)
  const setTitle = useModelStore((s) => s.setTitle)
  const addBoundary = useModelStore((s) => s.addBoundary)
  const { runLayout } = useElkLayout()
  const { exportAs } = useExportCanvas()
  const { screenToFlowPosition } = useReactFlow()
  const overlayMode = useModelStore((s) => s.overlayMode)
  const setOverlayMode = useModelStore((s) => s.setOverlayMode)
  const [laying, setLaying] = useState(false)

  return (
    <div
      className="px-3 py-2 flex flex-wrap items-center gap-3 text-sm rounded-lg shadow-lg"
      style={{
        border: '1px solid var(--border)',
        background: 'var(--surface-0)',
        color: 'var(--text-primary)',
      }}
    >
      <ProjectSwitcher
        projects={projects}
        currentProjectId={currentProjectId}
        onSwitch={onSwitchProject}
        onCreate={onCreateProject}
      />
      <div style={{ width: '1px', height: '20px', background: 'var(--border)' }} />
      <input
        aria-label={t('toolbar.title')}
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        className="font-medium bg-transparent outline-none min-w-0"
        style={{ width: '220px' }}
      />
      <button
        type="button"
        aria-label="Save model"
        title="Save the current model to this project"
        disabled={isSaving}
        onClick={onSave}
        className="px-2 py-1 rounded font-medium disabled:opacity-40"
        style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
      >
        {isSaving ? 'Saving…' : '💾 Save'}
      </button>
      {saveError && (
        <span className="text-xs" style={{ color: 'var(--severity-critical)' }} role="alert">
          Save failed: {saveError}
        </span>
      )}
      <div className="flex items-center gap-1" role="group" aria-label="Undo and redo">
        <button
          type="button"
          aria-label={t('toolbar.undo')}
          title={t('toolbar.undo')}
          disabled={!canUndo}
          onClick={() => undo()}
          className="px-2 py-1 rounded disabled:opacity-40"
          style={{ border: '1px solid var(--border)' }}
        >
          ↺ {t('toolbar.undoShort')}
        </button>
        <button
          type="button"
          aria-label={t('toolbar.redo')}
          title={t('toolbar.redo')}
          disabled={!canRedo}
          onClick={() => redo()}
          className="px-2 py-1 rounded disabled:opacity-40"
          style={{ border: '1px solid var(--border)' }}
        >
          ↻ {t('toolbar.redoShort')}
        </button>
      </div>
      <button
        type="button"
        aria-label={t('toolbar.autoLayout')}
        title={t('toolbar.autoLayout')}
        disabled={laying}
        onClick={async () => {
          setLaying(true)
          try {
            await runLayout()
          } finally {
            setLaying(false)
          }
        }}
        className="px-2 py-1 rounded disabled:opacity-40"
        style={{ border: '1px solid var(--border)' }}
      >
        {laying ? t('toolbar.layingOut') : `⇉ ${t('toolbar.autoLayout')}`}
      </button>
      <button
        type="button"
        aria-label="Add trust boundary"
        title="Add a trust boundary to the canvas — drag components onto it to place them inside"
        onClick={() => {
          const center = screenToFlowPosition({ x: window.innerWidth / 2, y: window.innerHeight / 2 })
          addBoundary(center)
        }}
        className="px-2 py-1 rounded"
        style={{ border: '1px solid var(--border)' }}
      >
        ⬚ Boundary
      </button>
      <button
        type="button"
        aria-label="Browse architecture templates"
        title="Templates"
        onClick={onOpenTemplates}
        className="px-2 py-1 rounded"
        style={{ border: '1px solid var(--border)' }}
      >
        Templates
      </button>
      <button
        type="button"
        aria-label="Compare model versions"
        title="Compare versions"
        onClick={onOpenDiff}
        className="px-2 py-1 rounded"
        style={{ border: '1px solid var(--border)' }}
      >
        Diff
      </button>
      <button
        type="button"
        aria-label="Toggle PHP DSL code view"
        title="Code"
        onClick={onToggleCode}
        className="px-2 py-1 rounded"
        style={{ border: '1px solid var(--border)' }}
      >
        Code
      </button>
      <label className="flex items-center gap-1.5">
        <span style={{ color: 'var(--text-secondary)' }}>{t('toolbar.overlay')}</span>
        <select
          aria-label="Canvas overlay mode"
          value={overlayMode}
          onChange={(e) => setOverlayMode(e.target.value as OverlayMode)}
          className="px-1.5 py-1 rounded text-sm"
          style={{ border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }}
        >
          {(Object.keys(OVERLAY_KEYS) as OverlayMode[]).map((mode) => (
            <option key={mode} value={mode}>
              {t(OVERLAY_KEYS[mode])}
            </option>
          ))}
        </select>
      </label>
      <div className="flex items-center gap-1" role="group" aria-label="Export canvas">
        <button
          type="button"
          aria-label="Export canvas as PNG"
          title="Export PNG"
          onClick={() => void exportAs('png')}
          className="px-2 py-1 rounded"
          style={{ border: '1px solid var(--border)' }}
        >
          {t('toolbar.exportPng')}
        </button>
        <button
          type="button"
          aria-label="Export canvas as SVG"
          title="Export SVG"
          onClick={() => void exportAs('svg')}
          className="px-2 py-1 rounded"
          style={{ border: '1px solid var(--border)' }}
        >
          {t('toolbar.exportSvg')}
        </button>
      </div>
      <label className="flex items-center gap-1.5">
        <span style={{ color: 'var(--text-secondary)' }}>{t('toolbar.language')}:</span>
        <select
          aria-label={t('toolbar.language')}
          value={i18n.resolvedLanguage}
          onChange={(e) => void i18n.changeLanguage(e.target.value)}
          className="px-1.5 py-1 rounded text-sm"
          style={{ border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }}
        >
          <option value="en">EN</option>
          <option value="ru">RU</option>
        </select>
      </label>
      <div className="ml-auto flex items-center gap-3">
        <SavedIndicator />
        <button
          type="button"
          aria-label="Log out"
          title="Log out"
          onClick={() => logout()}
          className="px-2 py-1 rounded"
          style={{ border: '1px solid var(--border)' }}
        >
          Log out
        </button>
      </div>
    </div>
  )
}
