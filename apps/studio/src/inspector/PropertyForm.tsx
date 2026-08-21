import type { KbPropertyDef, PropertyBag, PropertyValue } from '../api/types'

function isVisible(prop: KbPropertyDef, values: PropertyBag): boolean {
  if (!prop.show_if) return true
  return Object.entries(prop.show_if).every(([key, expected]) => values[key] === expected)
}

/** Auto-generates the inspector form from a KB component's property schema
 * (T-7.9) — field widget picked by `type`, grouped by `group`, hidden by
 * `show_if`. Editing a property is the "why did this threat appear" loop's
 * trigger: the caller re-runs analysis on every change. */
export function PropertyForm({
  properties,
  values,
  onChange,
}: {
  properties: KbPropertyDef[]
  values: PropertyBag
  onChange: (propertyId: string, value: PropertyValue) => void
}) {
  const groups = new Map<string, KbPropertyDef[]>()
  for (const prop of properties) {
    const key = prop.group ?? 'General'
    const list = groups.get(key) ?? []
    list.push(prop)
    groups.set(key, list)
  }

  return (
    <div className="flex flex-col gap-4">
      {[...groups.entries()].map(([group, props]) => (
        <div key={group}>
          <div className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-secondary)' }}>
            {group}
          </div>
          <div className="flex flex-col gap-2">
            {props.filter((p) => isVisible(p, values)).map((prop) => (
              <Field key={prop.id} prop={prop} value={values[prop.id]} onChange={(v) => onChange(prop.id, v)} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function Field({
  prop,
  value,
  onChange,
}: {
  prop: KbPropertyDef
  value: PropertyValue | undefined
  onChange: (value: PropertyValue) => void
}) {
  const labelEl = (
    <label className="text-sm flex-1" style={{ color: 'var(--text-primary)' }} title={prop.hint}>
      {prop.label}
    </label>
  )

  if (prop.type === 'boolean') {
    return (
      <div className="flex items-center justify-between">
        {labelEl}
        <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
      </div>
    )
  }

  if (prop.type === 'enum' && prop.enum) {
    return (
      <div className="flex flex-col gap-1">
        {labelEl}
        <select
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          className="text-sm px-2 py-1 rounded border"
          style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
        >
          {prop.enum.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </div>
    )
  }

  if (prop.type === 'number') {
    return (
      <div className="flex flex-col gap-1">
        {labelEl}
        <input
          type="number"
          value={typeof value === 'number' ? value : ''}
          onChange={(e) => onChange(Number(e.target.value))}
          className="text-sm px-2 py-1 rounded border"
          style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
        />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-1">
      {labelEl}
      <input
        type="text"
        value={typeof value === 'string' ? value : ''}
        onChange={(e) => onChange(e.target.value)}
        className="text-sm px-2 py-1 rounded border"
        style={{ background: 'var(--surface-0)', borderColor: 'var(--border)' }}
      />
    </div>
  )
}
