import { addCollection } from '@iconify/react'
import iconset from './iconset.generated.json'

/** Registers the offline icon subset (see scripts/build-iconset.mjs) with
 * @iconify/react so <Icon icon="mdi:aws" /> resolves locally — no request to
 * Iconify's API, matching the KB bundle's own offline-capable design. Import
 * this once, before any component renders an <Icon>. */
export function registerIcons(): void {
  for (const collection of Object.values(iconset)) {
    addCollection(collection as Parameters<typeof addCollection>[0])
  }
}

export const FALLBACK_ICON = 'mdi:cube-outline'
