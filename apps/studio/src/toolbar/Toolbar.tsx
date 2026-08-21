import { useEffect, useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import { useTranslation } from 'react-i18next'
import { useModelStore, useTemporalStore, type OverlayMode } from '../store/model.store'
import { useElkLayout } from '../layout/useElkLayout'
import { useExportCanvas } from '../canvas/useExportCanvas'
import { ProjectSwitcher } from './ProjectSwitcher'
import { logout, type ProjectSummary } from '../api/client'
import { Icon } from '@iconify/react'
import { IconButton, ToolbarDivider } from '../design/IconButton'
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

/** Two-tier app bar (T-7.x design pass): an identity/action row up top
 * (project, title, save status, the one colored primary action, sign-out)
 * and a dense icon-only tool row below it, grouped with dividers — mirrors
 * the separation most diagramming tools (draw.io, IriusRisk) use between
 * "what is this document and did it save" and "editing tools", instead of
 * one flat run of same-weight text buttons where nothing stands out. */
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

  // A solid, full-width docked bar (T-7.x UX pass) — not a floating card
  // positioned *over* the canvas. It used to be `position: absolute`, which
  // let it visually cover whatever the canvas/code panel rendered directly
  // underneath (a component near the top, the PHP code view's first lines);
  // moving it into normal document flow (App.tsx renders it as a sibling
  // row above the canvas, not an overlay on top of it) makes that
  // impossible by construction — there's no "underneath" left to cover.
  return (
    <div className="flex flex-col w-full" style={{ borderBottom: '1px solid var(--border)', background: 'var(--surface-0)' }}>
      <div
        className="px-3 py-2 flex flex-wrap items-center gap-3 text-sm"
        style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-primary)' }}
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
        <SavedIndicator />
        {saveError && (
          <span className="text-xs" style={{ color: 'var(--severity-critical)' }} role="alert">
            Save failed: {saveError}
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            aria-label={t('toolbar.save')}
            title={t('toolbar.save')}
            disabled={isSaving}
            onClick={onSave}
            className="px-3 py-1.5 rounded-md font-medium text-sm disabled:opacity-40"
            style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
          >
            {isSaving ? t('toolbar.saving') : t('toolbar.save')}
          </button>
          <IconButton icon="mdi:logout" label={t('toolbar.logOut')} onClick={() => logout()} />
        </div>
      </div>

      <div className="px-3 py-1.5 flex flex-wrap items-center gap-1.5">
        <div className="flex items-center gap-0.5" role="group" aria-label="Undo and redo">
          <IconButton icon="mdi:undo" label={t('toolbar.undo')} disabled={!canUndo} onClick={() => undo()} />
          <IconButton icon="mdi:redo" label={t('toolbar.redo')} disabled={!canRedo} onClick={() => redo()} />
        </div>

        <ToolbarDivider />

        <IconButton
          icon="mdi:sitemap-outline"
          label={laying ? t('toolbar.layingOut') : t('toolbar.autoLayout')}
          disabled={laying}
          onClick={async () => {
            setLaying(true)
            try {
              await runLayout()
            } finally {
              setLaying(false)
            }
          }}
        />
        <IconButton
          icon="mdi:vector-square"
          label={t('toolbar.addBoundary')}
          onClick={() => {
            const center = screenToFlowPosition({ x: window.innerWidth / 2, y: window.innerHeight / 2 })
            addBoundary(center)
          }}
        />

        <ToolbarDivider />

        <IconButton icon="mdi:view-grid-plus-outline" label={t('toolbar.templates')} onClick={onOpenTemplates} />
        <IconButton icon="mdi:compare-horizontal" label={t('toolbar.diff')} onClick={onOpenDiff} />
        <IconButton icon="mdi:code-tags" label={t('toolbar.code')} onClick={onToggleCode} />

        <ToolbarDivider />

        <label className="flex items-center gap-1.5 pl-1">
          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{t('toolbar.overlay')}</span>
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

        <ToolbarDivider />

        <div className="flex items-center gap-0.5" role="group" aria-label="Export canvas">
          <IconButton icon="mdi:file-image-outline" label={t('toolbar.exportPng')} onClick={() => void exportAs('png')} />
          <IconButton icon="mdi:svg" label={t('toolbar.exportSvg')} onClick={() => void exportAs('svg')} />
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <Icon icon="mdi:translate" width={16} height={16} style={{ color: 'var(--text-secondary)' }} aria-hidden="true" />
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
        </div>
      </div>
    </div>
  )
}
