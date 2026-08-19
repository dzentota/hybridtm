import { Icon } from '@iconify/react'
import { FALLBACK_ICON } from './icons'

/** Renders a KB component's `metadata.icon`/`metadata.color` (see
 * apps/api/kb/components/**\/*.yaml) as a tinted badge — used in both the
 * palette rows and canvas nodes so a component reads the same way in both
 * places. Falls back to a generic cube for any component missing an icon. */
export function ComponentIcon({
  icon,
  color,
  size = 16,
}: {
  icon: string | undefined
  color: string | undefined
  size?: number
}) {
  const tint = color ?? 'var(--text-secondary)'
  return (
    <span
      className="inline-flex items-center justify-center rounded-full shrink-0"
      style={{
        width: size + 10,
        height: size + 10,
        background: `color-mix(in srgb, ${tint} 16%, transparent)`,
      }}
    >
      <Icon icon={icon ?? FALLBACK_ICON} width={size} height={size} style={{ color: tint }} />
    </span>
  )
}
