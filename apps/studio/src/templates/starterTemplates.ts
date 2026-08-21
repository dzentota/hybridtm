export interface TemplateComponent {
  kbId: string
  x: number
  y: number
}

export interface TemplateEdge {
  from: number
  to: number
}

export interface StarterTemplate {
  id: string
  name: string
  description: string
  components: TemplateComponent[]
  edges: TemplateEdge[]
}

/** T-7.16's gallery, seeded client-side against real `kb-core` component
 * ids rather than waiting on the KB's own `kind: Template` entities (E8's
 * T-8.6, 6 KB-authored templates — not built yet, KB `templates` bundle is
 * empty). TemplateGallery filters out any template whose ids aren't in the
 * loaded KB, so this degrades gracefully rather than rendering broken
 * previews if a referenced component gets renamed. */
export const STARTER_TEMPLATES: StarterTemplate[] = [
  {
    id: 'classic-web-app',
    name: 'Classic web app',
    description: 'Browser → Nginx → Symfony → Postgres, with a Redis cache.',
    components: [
      { kbId: 'client-browser-spa', x: 0, y: 80 },
      { kbId: 'web-server-nginx', x: 260, y: 80 },
      { kbId: 'app-server-symfony', x: 520, y: 80 },
      { kbId: 'db-postgresql', x: 780, y: 0 },
      { kbId: 'cache-redis', x: 780, y: 160 },
    ],
    edges: [
      { from: 0, to: 1 },
      { from: 1, to: 2 },
      { from: 2, to: 3 },
      { from: 2, to: 4 },
    ],
  },
  {
    id: 'cdn-fronted-web-app',
    name: 'CDN-fronted web app',
    description: 'Adds a CDN/WAF in front of the classic web app for public internet exposure.',
    components: [
      { kbId: 'client-browser-spa', x: 0, y: 80 },
      { kbId: 'cdn-waf-cloudflare', x: 260, y: 80 },
      { kbId: 'web-server-nginx', x: 520, y: 80 },
      { kbId: 'app-server-symfony', x: 780, y: 80 },
      { kbId: 'db-postgresql', x: 1040, y: 80 },
    ],
    edges: [
      { from: 0, to: 1 },
      { from: 1, to: 2 },
      { from: 2, to: 3 },
      { from: 3, to: 4 },
    ],
  },
  {
    id: 'mobile-backend',
    name: 'Mobile app backend',
    description: 'Mobile client through an API gateway to a Node.js service and its datastores.',
    components: [
      { kbId: 'client-mobile-app', x: 0, y: 80 },
      { kbId: 'api-gateway-generic', x: 260, y: 80 },
      { kbId: 'app-server-nodejs', x: 520, y: 80 },
      { kbId: 'db-mysql', x: 780, y: 0 },
      { kbId: 'cache-redis', x: 780, y: 160 },
    ],
    edges: [
      { from: 0, to: 1 },
      { from: 1, to: 2 },
      { from: 2, to: 3 },
      { from: 2, to: 4 },
    ],
  },
  {
    id: 'authenticated-web-app',
    name: 'Web app with SSO + secrets',
    description: 'Classic web app plus a Keycloak identity provider and a Vault-backed secrets store.',
    components: [
      { kbId: 'client-browser-spa', x: 0, y: 120 },
      { kbId: 'web-server-nginx', x: 260, y: 120 },
      { kbId: 'app-server-symfony', x: 520, y: 120 },
      { kbId: 'db-postgresql', x: 780, y: 40 },
      { kbId: 'idp-keycloak', x: 520, y: 0 },
      { kbId: 'secrets-vault', x: 780, y: 200 },
    ],
    edges: [
      { from: 0, to: 1 },
      { from: 1, to: 2 },
      { from: 2, to: 3 },
      { from: 2, to: 4 },
      { from: 2, to: 5 },
    ],
  },
  {
    id: 'event-driven-pipeline',
    name: 'Event-driven pipeline',
    description: 'Producer service through a message queue to a worker, landing in object storage and search.',
    components: [
      { kbId: 'app-server-nodejs', x: 0, y: 80 },
      { kbId: 'queue-rabbitmq', x: 260, y: 80 },
      { kbId: 'app-server-symfony', x: 520, y: 80 },
      { kbId: 'object-storage-generic', x: 780, y: 0 },
      { kbId: 'search-elasticsearch', x: 780, y: 160 },
    ],
    edges: [
      { from: 0, to: 1 },
      { from: 1, to: 2 },
      { from: 2, to: 3 },
      { from: 2, to: 4 },
    ],
  },
  {
    id: 'api-gateway-microservices',
    name: 'API gateway + microservices',
    description: 'Gateway fanning out to two independent services over Kafka, each with its own datastore.',
    components: [
      { kbId: 'client-browser-spa', x: 0, y: 120 },
      { kbId: 'api-gateway-generic', x: 260, y: 120 },
      { kbId: 'app-server-nodejs', x: 520, y: 40 },
      { kbId: 'app-server-symfony', x: 520, y: 200 },
      { kbId: 'queue-kafka', x: 780, y: 120 },
      { kbId: 'db-mongodb', x: 1040, y: 40 },
      { kbId: 'db-mysql', x: 1040, y: 200 },
    ],
    edges: [
      { from: 0, to: 1 },
      { from: 1, to: 2 },
      { from: 1, to: 3 },
      { from: 2, to: 4 },
      { from: 3, to: 4 },
      { from: 2, to: 5 },
      { from: 3, to: 6 },
    ],
  },
]
