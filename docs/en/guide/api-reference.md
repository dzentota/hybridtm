# API Reference

Base URL in local dev: `http://127.0.0.1:8000`. All routes except
`/login_check` require `Authorization: Bearer <token>` — either a JWT
from `/login_check` or a long-lived `htm_...` token from
`POST /api-tokens`.

## Authentication

| Method | Path | Notes |
|---|---|---|
| `POST` | `/login_check` | Body `{"email", "password"}` → `{"token"}` (JWT). No self-service registration — accounts are created via `app:create-user`. |
| `POST` | `/api-tokens` | Mints a long-lived `htm_...` token for the caller's own account. The plaintext is returned exactly once. |

## Resources (API Platform: `GET`/`POST`/`PUT`/`DELETE`)

| Resource | Path prefix | Notes |
|---|---|---|
| Threat model projects | `/api/threat_model_projects` | Any authenticated user can create one and becomes its project Admin automatically. |
| Model versions | `/api/model_versions` | `PUT` is blocked once `status` reaches `approved`/`superseded` — create a new version instead. |
| Risk decisions | `/api/risk_decision_records` | Keyed by `(project, findingStableId)` — survives across model versions where the same finding reproduces. |
| Project memberships | `/api/project_memberships` | 5 roles: Viewer, Modeler, Reviewer, KbAuthor, Admin (project-scoped). |
| Audit log | `/api/audit_log_entries` | Read-only, `ROLE_ADMIN` only. One entry per create/update/delete, `patch` is an RFC 6902 JSON Patch fragment. |
| Users | `/api/users/{id}` | `Get` only, no listing — resolves IRI references (e.g. `ProjectMembership.user`). |

## Model analysis

| Method | Path | Notes |
|---|---|---|
| `GET` | `/kb/bundle` | The whole merged KB as JSON. ETag = KB content hash; supports `If-None-Match` → 304. |
| `POST` | `/model-versions/{id}/analyze` | Synchronous, no persistence — the "check as you edit" path. |
| `POST` | `/model-versions/{id}/analyze/deep` | Dispatches a Threagile-backed job to the async worker; returns 202 + a job id immediately. |
| `GET` | `/deep-analysis-results/{id}` | One-shot JSON snapshot of a deep-analysis job. |
| `GET` | `/deep-analysis-results/{id}/events` | Same data as an SSE stream, polling until a terminal status. |
| `GET` | `/model-versions/{id}/findings` | Fast-analysis findings joined with any recorded risk decision. |

## Export & reporting

| Method | Path | Formats |
|---|---|---|
| `GET` | `/model-versions/{id}/export/{format}` | `json`, `php`, `threagile`, `otm` (round-trip); `sarif`, `mermaid`, `dot` (one-way). |
| `GET` | `/model-versions/{id}/report/{format}` | `pdf`, `docx`, `xlsx` — title/summary/DFD/risk-register/countermeasures/standards appendix. |
| `POST` | `/threat-model-projects/{id}/import/{format}` | `json`, `php`, `threagile`, `otm`. PHP import surfaces non-canonical constructs as warnings rather than failing. |
| `POST` | `/model-versions/{id}/scanner-findings/{tool}` | `checkov`, `trivy`, `sonarqube`. A passing check mapped to a countermeasure (`config/scanner-mappings.yaml`) auto-mitigates matching findings; never overrides an existing human decision. |

## Workflow & model versions {#workflow-model-versions}

`ModelVersion.status`: `draft` → `in_review` → `approved` →
`superseded`. Approved/superseded are immutable (`PUT` 403s regardless
of role).

| Method | Path | Role required |
|---|---|---|
| `POST` | `/model-versions/{id}/submit-for-review` | Modeler+ |
| `POST` | `/model-versions/{id}/request-changes` | Reviewer+ |
| `POST` | `/model-versions/{id}/approve` | Reviewer+, blocked by `policy.yaml` violations (422 with per-violation reasons) |

Approving one version automatically supersedes whatever was previously
`approved` for the same project.

## RBAC

Every project-scoped endpoint checks a `ProjectVoter` attribute against
the caller's `ProjectMembership` for that specific project — cross-tenant
access returns 404 (Postgres row-level security makes the row
invisible, not merely forbidden), same-tenant access without the right
role returns 403. `ROLE_ADMIN` (a tenant-wide flag, separate from a
project's own Admin membership) bypasses the per-project check entirely.

| Attribute | Granted to |
|---|---|
| `PROJECT_VIEW` | Every role |
| `PROJECT_EDIT_MODEL` | Modeler, Admin |
| `PROJECT_DECIDE_RISK` | Reviewer, Admin |
| `PROJECT_MANAGE_MEMBERS` | Admin |
| `PROJECT_DELETE` | Admin |
