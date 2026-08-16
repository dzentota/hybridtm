# HybridTM Studio

The canvas-based threat-modeling editor (E7 of the plan — see
`hybridtm-studio-plan_1.md` at the repo root). Vite + React 19 + TypeScript,
talking to the Symfony API in `apps/api/`.

## Stack

- `@xyflow/react` (React Flow 12) — the canvas
- Zustand — client-side model state
- TanStack Query — server state (KB bundle, analysis runs)
- Tailwind CSS 4 — design tokens and layout

## Scope of this pass

This is the core MVP loop, not the full 22-task E7 spec: canvas
(component/boundary nodes, data-flow edges), component palette, property
inspector, and the findings panel with rule-trace ("why did this fire?").
Deliberately not yet built: undo/redo, i18n, full accessibility pass, ELK
auto-layout, Monaco split-view, PNG/SVG export, command palette, overlay
modes, diff view, template gallery.

## Running

Requires the API (`apps/api/`) running against Postgres/Redis
(`docker-compose up` at the repo root) and at least one user
(`php bin/console app:create-user email password --role=ROLE_EDITOR`
from `apps/api/`).

```bash
npm install
npm run dev
```

The dev server proxies `/api`, `/kb`, `/model-versions`,
`/threat-model-projects`, `/deep-analysis-results`, `/login_check`, and
`/api-tokens` to `http://127.0.0.1:8000` (see `vite.config.ts`).
