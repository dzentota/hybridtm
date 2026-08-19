import { Icon } from '@iconify/react'
import { FALLBACK_ICON } from './icons'

/** Small icon-only chrome button shared by the top toolbar and the
 * per-node hover toolbar — consistent size/hover state so both read as
 * the same design language instead of each screen inventing its own
 * button style. Always carries a visible tooltip (`title`) and an
 * `aria-label` since there is no text label to fall back on. */
export function IconButton({
  icon,
  label,
  onClick,
  disabled,
  active,
  variant = 'ghost',
}: {
  icon: string
  label: string
  onClick?: () => void
  disabled?: boolean
  active?: boolean
  variant?: 'ghost' | 'primary' | 'danger'
}) {
  // Background/hover MUST live in the className, not in an inline `style`:
  // an inline style always wins over a class's `:hover` rule regardless of
  // specificity, so a button whose resting background was set via
  // `style={{ background: 'transparent' }}` could never visibly react to
  // `hover:bg-...` — the inline value simply overrode it at every pixel,
  // hover included. Only color/border (states we don't hover-change) stay
  // in a plain object; the interactive part is Tailwind classes end to end.
  const variantClass =
    variant === 'primary'
      ? 'bg-(--accent) text-(--accent-contrast) hover:enabled:brightness-110'
      : variant === 'danger'
        ? 'text-(--severity-critical) hover:enabled:bg-(--surface-2)'
        : `text-(--text-primary) hover:enabled:bg-(--surface-2) ${active ? 'bg-(--surface-2)' : 'bg-transparent'}`

  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex items-center justify-center w-8 h-8 rounded-md shrink-0 border border-transparent transition-colors disabled:opacity-40 disabled:cursor-not-allowed focus-visible:outline focus-visible:outline-2 focus-visible:outline-(--accent) ${variantClass}`}
    >
      <Icon icon={icon ?? FALLBACK_ICON} width={17} height={17} />
    </button>
  )
}

/** Thin vertical rule between toolbar button groups. */
export function ToolbarDivider() {
  return <div style={{ width: '1px', height: '22px', background: 'var(--border)' }} />
}
