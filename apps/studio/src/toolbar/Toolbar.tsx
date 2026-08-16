import { useEffect, useState } from 'react'
import { useModelStore, useTemporalStore } from '../store/model.store'
import { useElkLayout } from '../layout/useElkLayout'
import type { KbBundle } from '../api/types'

function SavedIndicator() {
  const lastSavedAt = useModelStore((s) => s.lastSavedAt)
  const [, forceTick] = useState(0)

  useEffect(() => {
    const id = setInterval(() => forceTick((n) => n + 1), 15_000)
    return () => clearInterval(id)
  }, [])

  if (!lastSavedAt) return <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Not saved yet</span>

  const seconds = Math.max(0, Math.round((Date.now() - new Date(lastSavedAt).getTime()) / 1000))
  const label = seconds < 5 ? 'Saved just now' : seconds < 60 ? `Saved ${seconds}s ago` : `Saved ${Math.round(seconds / 60)}m ago`
  return (
    <span className="text-xs" style={{ color: 'var(--text-secondary)' }} aria-live="polite">
      {label}
    </span>
  )
}

export function Toolbar({ kb: _kb }: { kb: KbBundle | undefined }) {
  const { undo, redo, canUndo, canRedo } = useTemporalStore()
  const title = useModelStore((s) => s.title)
  const setTitle = useModelStore((s) => s.setTitle)
  const { runLayout } = useElkLayout()
  const [laying, setLaying] = useState(false)

  return (
    <div
      className="px-3 py-2 flex items-center gap-3 text-sm"
      style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-primary)' }}
    >
      <input
        aria-label="Model title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        className="font-medium bg-transparent outline-none min-w-0"
        style={{ width: '220px' }}
      />
      <div className="flex items-center gap-1" role="group" aria-label="Undo and redo">
        <button
          type="button"
          aria-label="Undo (Ctrl+Z)"
          title="Undo (Ctrl+Z)"
          disabled={!canUndo}
          onClick={() => undo()}
          className="px-2 py-1 rounded disabled:opacity-40"
          style={{ border: '1px solid var(--border)' }}
        >
          ↺ Undo
        </button>
        <button
          type="button"
          aria-label="Redo (Ctrl+Shift+Z)"
          title="Redo (Ctrl+Shift+Z)"
          disabled={!canRedo}
          onClick={() => redo()}
          className="px-2 py-1 rounded disabled:opacity-40"
          style={{ border: '1px solid var(--border)' }}
        >
          ↻ Redo
        </button>
      </div>
      <button
        type="button"
        aria-label="Auto-layout the canvas with ELK"
        title="Auto-layout"
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
        {laying ? 'Laying out…' : '⇉ Auto-layout'}
      </button>
      <div className="ml-auto flex items-center gap-3">
        <SavedIndicator />
      </div>
    </div>
  )
}
