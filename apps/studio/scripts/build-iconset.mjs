#!/usr/bin/env node
// Regenerates src/design/iconset.generated.json: a small offline subset of
// the icon collections KB component YAML files reference via `icon:
// <prefix>:<name>` (see apps/api/kb/components/**/*.yaml). Pulling the full
// @iconify-json/* packages into the bundle would ship thousands of unused
// icons; this keeps only what the KB actually names, listed in
// KB_ICON_ALLOWLIST below.
//
// Re-run after adding a new `icon:` value to any KB component:
//   node scripts/build-iconset.mjs
// and add the new identifier to KB_ICON_ALLOWLIST first.
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { getIcons } from '@iconify/utils'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT_PATH = resolve(__dirname, '../src/design/iconset.generated.json')

const KB_ICON_ALLOWLIST = [
  'material-symbols:api',
  'material-symbols:cloud-outline',
  'material-symbols:folder-shared-outline',
  'material-symbols:smartphone-outline',
  'material-symbols:web',
  'mdi:account-key-outline',
  'mdi:application-braces-outline',
  'mdi:archive-outline',
  'mdi:aws',
  'mdi:bucket-outline',
  'mdi:chip',
  'mdi:clock-outline',
  'mdi:console',
  'mdi:credit-card-outline',
  'mdi:database-outline',
  'mdi:database-search-outline',
  'mdi:devices',
  'mdi:dns-outline',
  'mdi:email-outline',
  'mdi:handshake-outline',
  'mdi:infinity',
  'mdi:key-chain',
  'mdi:key-variant',
  'mdi:lock-outline',
  'mdi:memory',
  'mdi:monitor',
  'mdi:monitor-dashboard',
  'mdi:package-variant-closed',
  'mdi:router-network',
  'mdi:shield-lock-outline',
  'mdi:table',
  'mdi:tray-full',
  'mdi:web',
  'simple-icons:amazonecs',
  'simple-icons:amazoneks',
  'simple-icons:amazons3',
  'simple-icons:apache',
  'simple-icons:apachekafka',
  'simple-icons:awslambda',
  'simple-icons:clickhouse',
  'simple-icons:cloudflare',
  'simple-icons:django',
  'simple-icons:dotnet',
  'simple-icons:elastic',
  'simple-icons:elasticsearch',
  'simple-icons:envoyproxy',
  'simple-icons:githubactions',
  'simple-icons:gitlab',
  'simple-icons:jenkins',
  'simple-icons:keycloak',
  'simple-icons:mongodb',
  'simple-icons:mysql',
  'simple-icons:natsdotio',
  'simple-icons:nginx',
  'simple-icons:nodedotjs',
  'simple-icons:opentelemetry',
  'simple-icons:postgresql',
  'simple-icons:prometheus',
  'simple-icons:rabbitmq',
  'simple-icons:redis',
  'simple-icons:sentry',
  'simple-icons:spring',
  'simple-icons:symfony',
  'simple-icons:traefikproxy',
  'simple-icons:vault',
  // Generic fallback for any KB component that ships no icon of its own.
  'mdi:cube-outline',
]

const byPrefix = new Map()
for (const id of KB_ICON_ALLOWLIST) {
  const [prefix, name] = id.split(':')
  if (!prefix || !name) throw new Error(`Malformed icon id: ${id}`)
  if (!byPrefix.has(prefix)) byPrefix.set(prefix, [])
  byPrefix.get(prefix).push(name)
}

const result = {}
const missing = []
for (const [prefix, names] of byPrefix) {
  const fullSet = JSON.parse(readFileSync(resolve(__dirname, `../node_modules/@iconify-json/${prefix}/icons.json`), 'utf8'))
  const subset = getIcons(fullSet, names)
  if (!subset) throw new Error(`getIcons returned nothing for prefix ${prefix}`)
  for (const name of names) {
    if (!subset.icons[name]) missing.push(`${prefix}:${name}`)
  }
  result[prefix] = subset
}

if (missing.length > 0) {
  console.error('Icon names not found in their collection:', missing)
  process.exit(1)
}

writeFileSync(OUT_PATH, JSON.stringify(result))
console.log(`Wrote ${OUT_PATH} (${KB_ICON_ALLOWLIST.length} icons across ${byPrefix.size} collections)`)
