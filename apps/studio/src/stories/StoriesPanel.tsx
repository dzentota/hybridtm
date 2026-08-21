import { useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useModelStore } from '../store/model.store'
import type { AbuserStoryStatus, KbBundle, StoryCoverage } from '../api/types'

const statusColor: Record<string, string> = {
  covered: 'var(--severity-low, #3d8b5a)',
  partial: 'var(--severity-medium, #b8860b)',
  uncovered: 'var(--severity-critical)',
  accepted: 'var(--text-secondary)',
  open: 'var(--text-secondary)',
  'in-progress': 'var(--severity-medium, #b8860b)',
  mitigated: 'var(--severity-low, #3d8b5a)',
}

function coverageFor(storyId: string, list: StoryCoverage[]): StoryCoverage | undefined {
  return list.find((c) => c.storyId === storyId)
}

function slugify(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
}

/** Abuser Stories list + editor with canvas highlight of linked assets/flows. */
export function StoriesPanel({ kb }: { kb: KbBundle | undefined }) {
  const { t } = useTranslation()
  const {
    abuseCases,
    storyCoverage,
    selectedStoryId,
    selectStory,
    addAbuseCase,
    updateAbuseCase,
    removeAbuseCase,
    nodes,
    edges,
    dataAssets,
  } = useModelStore()

  const selected = abuseCases.find((c) => c.title === selectedStoryId) ?? null
  const coverage = selected ? coverageFor(selected.title, storyCoverage) : undefined

  const actors = useMemo(
    () => nodes.filter((n) => n.data.kind === 'component' && n.data.traits.includes('threat_actor')),
    [nodes],
  )
  const components = useMemo(() => nodes.filter((n) => n.data.kind === 'component'), [nodes])
  const threatIds = useMemo(() => Object.keys(kb?.threats ?? {}).sort(), [kb])

  return (
    <div className="flex flex-col h-full min-h-0" style={{ background: 'var(--surface-1)' }}>
      <div className="p-3 flex flex-col gap-2 shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            {t('stories.title')}
          </span>
          <button
            type="button"
            className="text-xs font-medium px-2 py-1 rounded"
            style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
            onClick={() => addAbuseCase({ text: '' })}
          >
            {t('stories.add')}
          </button>
        </div>
        {abuseCases.length === 0 && (
          <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            {t('stories.empty')}
          </div>
        )}
        <ul className="flex flex-col gap-1 max-h-36 overflow-y-auto">
          {abuseCases.map((story) => {
            const cov = coverageFor(story.title, storyCoverage)
            const badge = cov?.status ?? story.status ?? 'open'
            return (
              <li key={story.title}>
                <button
                  type="button"
                  onClick={() => selectStory(story.title)}
                  className="w-full text-left text-xs px-2 py-1.5 rounded flex items-center justify-between gap-2"
                  style={{
                    background: selectedStoryId === story.title ? 'var(--surface-2)' : 'transparent',
                    border: selectedStoryId === story.title ? '1px solid var(--accent)' : '1px solid transparent',
                    color: 'var(--text-primary)',
                  }}
                >
                  <span className="truncate font-medium">{story.title}</span>
                  <span className="shrink-0 capitalize" style={{ color: statusColor[badge] ?? 'var(--text-secondary)' }}>
                    {badge}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      </div>

      {selected && (
        <div className="flex-1 min-h-0 overflow-y-auto p-3 flex flex-col gap-3 text-xs">
          {coverage && (
            <div
              className="rounded px-2 py-1.5"
              style={{ background: 'var(--surface-2)', color: statusColor[coverage.status] }}
            >
              {t('stories.coverage', {
                status: coverage.status,
                covered: coverage.coveredCwes.join(', ') || '—',
                missing: coverage.missingCwes.join(', ') || '—',
              })}
              {coverage.issues.length > 0 && (
                <div className="mt-1" style={{ color: 'var(--severity-critical)' }}>
                  {coverage.issues.join('; ')}
                </div>
              )}
            </div>
          )}

          <Field label={t('stories.id')}>
            <input
              className="w-full px-2 py-1 rounded border text-xs"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={selected.title}
              onChange={(e) => {
                const next = slugify(e.target.value)
                if (next && next !== selected.title) {
                  updateAbuseCase(selected.title, { title: next })
                }
              }}
            />
          </Field>

          <Field label={t('stories.asA')}>
            <input
              className="w-full px-2 py-1 rounded border text-xs"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={selected.asA ?? ''}
              onChange={(e) => updateAbuseCase(selected.title, { asA: e.target.value })}
              placeholder="anonymous attacker"
            />
          </Field>
          <Field label={t('stories.iWant')}>
            <input
              className="w-full px-2 py-1 rounded border text-xs"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={selected.iWant ?? ''}
              onChange={(e) => updateAbuseCase(selected.title, { iWant: e.target.value })}
            />
          </Field>
          <Field label={t('stories.soThat')}>
            <input
              className="w-full px-2 py-1 rounded border text-xs"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={selected.soThat ?? ''}
              onChange={(e) => updateAbuseCase(selected.title, { soThat: e.target.value })}
            />
          </Field>
          <Field label={t('stories.description')}>
            <textarea
              className="w-full px-2 py-1 rounded border text-xs min-h-[56px]"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={selected.text}
              onChange={(e) => updateAbuseCase(selected.title, { text: e.target.value })}
            />
          </Field>

          <Field label={t('stories.actor')}>
            <select
              className="w-full px-2 py-1 rounded border text-xs"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={selected.actorId ?? ''}
              onChange={(e) => updateAbuseCase(selected.title, { actorId: e.target.value || null })}
            >
              <option value="">—</option>
              {actors.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.data.name} ({n.id})
                </option>
              ))}
            </select>
          </Field>

          <MultiSelect
            label={t('stories.assets')}
            options={components.map((n) => ({ id: n.id, label: n.data.name }))}
            selected={selected.assetIds ?? []}
            onChange={(assetIds) => updateAbuseCase(selected.title, { assetIds })}
          />
          <MultiSelect
            label={t('stories.flows')}
            options={edges.map((e) => ({ id: e.id, label: `${e.source} → ${e.target}` }))}
            selected={selected.dataFlowIds ?? []}
            onChange={(dataFlowIds) => updateAbuseCase(selected.title, { dataFlowIds })}
          />
          <MultiSelect
            label={t('stories.dataAssets')}
            options={dataAssets.map((a) => ({ id: a.id, label: a.name }))}
            selected={selected.dataAssetIds ?? []}
            onChange={(dataAssetIds) => updateAbuseCase(selected.title, { dataAssetIds })}
          />
          <MultiSelect
            label={t('stories.threats')}
            options={threatIds.map((id) => ({ id, label: kb?.threats[id]?.title ?? id }))}
            selected={selected.threatIds ?? []}
            onChange={(threatIds) => updateAbuseCase(selected.title, { threatIds })}
          />

          <Field label={t('stories.requiredCwes')}>
            <input
              className="w-full px-2 py-1 rounded border text-xs"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={(selected.requiredCwes ?? []).join(', ')}
              onChange={(e) =>
                updateAbuseCase(selected.title, {
                  requiredCwes: e.target.value
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean),
                })
              }
              placeholder="CWE-307, CWE-521"
            />
          </Field>

          <Field label={t('stories.status')}>
            <select
              className="w-full px-2 py-1 rounded border text-xs"
              style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
              value={selected.status ?? 'open'}
              onChange={(e) => updateAbuseCase(selected.title, { status: e.target.value as AbuserStoryStatus })}
            >
              <option value="open">open</option>
              <option value="in-progress">in-progress</option>
              <option value="mitigated">mitigated</option>
              <option value="accepted">accepted</option>
            </select>
          </Field>

          <button
            type="button"
            className="text-xs px-2 py-1 rounded self-start"
            style={{ border: '1px solid var(--border)', color: 'var(--severity-critical)' }}
            onClick={() => removeAbuseCase(selected.title)}
          >
            {t('stories.delete')}
          </button>
        </div>
      )}
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
      {children}
    </label>
  )
}

function MultiSelect({
  label,
  options,
  selected,
  onChange,
}: {
  label: string
  options: { id: string; label: string }[]
  selected: string[]
  onChange: (ids: string[]) => void
}) {
  const [q, setQ] = useState('')
  const filtered = options.filter(
    (o) => o.label.toLowerCase().includes(q.toLowerCase()) || o.id.toLowerCase().includes(q.toLowerCase()),
  )

  return (
    <div className="flex flex-col gap-1">
      <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <input
        className="w-full px-2 py-1 rounded border text-xs"
        style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Filter…"
      />
      <div className="max-h-24 overflow-y-auto flex flex-col gap-0.5 rounded border p-1" style={{ borderColor: 'var(--border)' }}>
        {filtered.length === 0 && <span style={{ color: 'var(--text-secondary)' }}>—</span>}
        {filtered.map((o) => {
          const on = selected.includes(o.id)
          return (
            <label key={o.id} className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={on}
                onChange={() => onChange(on ? selected.filter((id) => id !== o.id) : [...selected, o.id])}
              />
              <span className="truncate">{o.label}</span>
            </label>
          )
        })}
      </div>
    </div>
  )
}

/** Used by canvas nodes/edges to know if they belong to the selected story. */
export function useStoryHighlight(): { nodeIds: Set<string>; edgeIds: Set<string> } {
  const selectedStoryId = useModelStore((s) => s.selectedStoryId)
  const abuseCases = useModelStore((s) => s.abuseCases)
  return useMemo(() => {
    const story = abuseCases.find((c) => c.title === selectedStoryId)
    if (!story) return { nodeIds: new Set<string>(), edgeIds: new Set<string>() }
    const nodeIds = new Set<string>([...(story.assetIds ?? []), ...(story.actorId ? [story.actorId] : [])])
    const edgeIds = new Set<string>(story.dataFlowIds ?? [])
    return { nodeIds, edgeIds }
  }, [selectedStoryId, abuseCases])
}
