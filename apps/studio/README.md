# HybridTM Studio

The canvas-based threat-modeling editor (E7 of the plan — see
`hybridtm-studio-plan_1.md` at the repo root). Vite + React 19 + TypeScript,
talking to the Symfony API in `apps/api/`.

## Stack

- `@xyflow/react` (React Flow 12) — the canvas
- Zustand — client-side model state
- TanStack Query — server state (KB bundle, analysis runs)
- Tailwind CSS 4 — design tokens and layout

## What you get

Core loop for architecture threat modeling plus **Abuser Stories**:

- Canvas (component / boundary nodes, data-flow edges)
- Component palette and property inspector
- Findings panel with rule-trace ("why did this fire?")
- **Stories** tab — CRUD Abuser Stories, link actors / assets / flows / KB
  threats / CWEs, coverage badges from analyze `storyCoverage`, canvas
  highlight for the selected story

Also present in-tree (beyond the original MVP notes): undo/redo, i18n,
ELK layout, PHP sync panel, command palette, overlays, diff, templates —
see the app itself for the current surface area.

Code-level story verification (`#[AbuserStory]` + `#[Mitigation]`) is
enforced in CI via `hybridtm analyze --source=… --fail-on-uncovered-stories`.
Studio shows coverage when the analyze API returns `storyCoverage`.

Docs: [Abuser Stories guide](../../docs/en/guide/abuser-stories.md).

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
