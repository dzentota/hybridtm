import { useEffect, useMemo, useRef, useState } from 'react'
import { fuzzyMatch } from './fuzzy'
import { useCommands } from './useCommands'
import type { KbBundle } from '../api/types'

/** Cmd/Ctrl+K command palette (T-7.18). Fuzzy-filters the full command list
 * (static canvas/view actions + one "Add <component>" entry per KB
 * component) and runs the selected one on Enter. */
export function CommandPalette({ kb, onRunAnalysis }: { kb: KbBundle | undefined; onRunAnalysis: () => void }) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const commands = useCommands(kb, onRunAnalysis)

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey
      if (meta && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
        return
      }
      if (e.key === 'Escape' && open) setOpen(false)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open])

  useEffect(() => {
    if (open) {
      setQuery('')
      setActiveIndex(0)
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [open])

  const filtered = useMemo(() => commands.filter((c) => fuzzyMatch(query, c.label)).slice(0, 50), [commands, query])

  if (!open) return null

  const run = (index: number) => {
    filtered[index]?.run()
    setOpen(false)
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-32"
      style={{ background: 'color-mix(in srgb, black 30%, transparent)' }}
      role="presentation"
      onClick={() => setOpen(false)}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="w-[480px] max-h-[60vh] rounded-lg shadow-xl overflow-hidden flex flex-col"
        style={{ background: 'var(--surface-0)', border: '1px solid var(--border)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            setActiveIndex(0)
          }}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              setActiveIndex((i) => Math.min(i + 1, filtered.length - 1))
            } else if (e.key === 'ArrowUp') {
              e.preventDefault()
              setActiveIndex((i) => Math.max(i - 1, 0))
            } else if (e.key === 'Enter') {
              e.preventDefault()
              run(activeIndex)
            }
          }}
          placeholder="Type a command…"
          aria-label="Command search"
          className="px-3 py-2.5 text-sm outline-none"
          style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-primary)', background: 'transparent' }}
        />
        <div className="overflow-y-auto" role="listbox" aria-label="Commands">
          {filtered.length === 0 && (
            <div className="px-3 py-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
              No matching commands
            </div>
          )}
          {filtered.map((c, i) => (
            <div
              key={c.id}
              role="option"
              aria-selected={i === activeIndex}
              onMouseEnter={() => setActiveIndex(i)}
              onClick={() => run(i)}
              className="px-3 py-1.5 text-sm flex items-center justify-between cursor-pointer"
              style={{
                background: i === activeIndex ? 'var(--surface-2)' : 'transparent',
                color: 'var(--text-primary)',
              }}
            >
              <span>{c.label}</span>
              <span className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                {c.group}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
