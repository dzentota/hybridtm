# Справочник API

Базовый URL для локальной разработки: `http://127.0.0.1:8000`. Все
маршруты, кроме `/login_check`, требуют `Authorization: Bearer <token>` — либо JWT из `/login_check`, либо долгоживущий токен
`htm_...` из `POST /api-tokens`.

## Аутентификация

| Метод | Путь | Примечания |
|---|---|---|
| `POST` | `/login_check` | Тело `{"email", "password"}` → `{"token"}` (JWT). Самостоятельной регистрации нет — аккаунты создаются через `app:create-user`. |
| `POST` | `/api-tokens` | Выпускает долгоживущий токен `htm_...` для аккаунта вызывающего. Открытый текст возвращается ровно один раз. |

## Ресурсы (API Platform: `GET`/`POST`/`PUT`/`DELETE`)

| Ресурс | Префикс пути | Примечания |
|---|---|---|
| Проекты моделей угроз | `/api/threat_model_projects` | Любой аутентифицированный пользователь может создать проект и автоматически становится его Admin. |
| Версии модели | `/api/model_versions` | `PUT` блокируется, как только `status` достигает `approved`/`superseded` — вместо этого создайте новую версию. |
| Решения по рискам | `/api/risk_decision_records` | Ключ — `(project, findingStableId)` — сохраняется между версиями модели, где та же находка воспроизводится снова. |
| Участники проекта | `/api/project_memberships` | 5 ролей: Viewer, Modeler, Reviewer, KbAuthor, Admin (в рамках проекта). |
| Журнал аудита | `/api/audit_log_entries` | Только чтение, только `ROLE_ADMIN`. Одна запись на создание/изменение/удаление, `patch` — фрагмент JSON Patch (RFC 6902). |
| Пользователи | `/api/users/{id}` | Только `Get`, без листинга — разрешает IRI-ссылки (например, `ProjectMembership.user`). |

## Анализ модели

| Метод | Путь | Примечания |
|---|---|---|
| `GET` | `/kb/bundle` | Вся объединённая KB в виде JSON. ETag = хеш содержимого KB; поддерживает `If-None-Match` → 304. |
| `POST` | `/model-versions/{id}/analyze` | Синхронно, без сохранения — путь «проверка по мере редактирования». |
| `POST` | `/model-versions/{id}/analyze/deep` | Отправляет задачу на основе Threagile в асинхронный воркер; сразу возвращает 202 + id задачи. |
| `GET` | `/deep-analysis-results/{id}` | Разовый JSON-снимок задачи глубокого анализа. |
| `GET` | `/deep-analysis-results/{id}/events` | Те же данные в виде SSE-потока, опрос до достижения финального статуса. |
| `GET` | `/model-versions/{id}/findings` | Находки быстрого анализа, объединённые с зафиксированными решениями по рискам. |

## Экспорт и отчёты

| Метод | Путь | Форматы |
|---|---|---|
| `GET` | `/model-versions/{id}/export/{format}` | `json`, `php`, `threagile`, `otm` (двусторонние); `sarif`, `mermaid`, `dot` (только экспорт). |
| `GET` | `/model-versions/{id}/report/{format}` | `pdf`, `docx`, `xlsx` — титул/сводка/DFD/реестр рисков/контрмеры/приложение со стандартами. |
| `POST` | `/threat-model-projects/{id}/import/{format}` | `json`, `php`, `threagile`, `otm`. Импорт PHP выводит неканонические конструкции как предупреждения, а не ошибку. |
| `POST` | `/model-versions/{id}/scanner-findings/{tool}` | `checkov`, `trivy`, `sonarqube`. Пройденная проверка, сопоставленная с контрмерой (`config/scanner-mappings.yaml`), автоматически переводит совпадающие находки в mitigated; никогда не переопределяет уже принятое человеком решение. |

## Workflow и версии модели {#workflow-model-versions}

`ModelVersion.status`: `draft` → `in_review` → `approved` →
`superseded`. Approved/superseded неизменяемы (`PUT` вернёт 403 вне
зависимости от роли).

| Метод | Путь | Требуемая роль |
|---|---|---|
| `POST` | `/model-versions/{id}/submit-for-review` | Modeler и выше |
| `POST` | `/model-versions/{id}/request-changes` | Reviewer и выше |
| `POST` | `/model-versions/{id}/approve` | Reviewer и выше, блокируется нарушениями `policy.yaml` (422 с причиной по каждому нарушению) |

Одобрение одной версии автоматически переводит предыдущую `approved`
версию того же проекта в `superseded`.

## RBAC

Каждый эндпоинт в рамках проекта проверяет атрибут `ProjectVoter`
против `ProjectMembership` вызывающего для конкретного проекта —
межтенантный доступ возвращает 404 (Postgres row-level security делает
строку невидимой, а не просто запрещённой), доступ в рамках того же
тенанта без нужной роли возвращает 403. `ROLE_ADMIN` (тенантный флаг,
отдельный от собственного членства Admin в проекте) полностью обходит
проверку на уровне проекта.

| Атрибут | Кому предоставляется |
|---|---|
| `PROJECT_VIEW` | Любая роль |
| `PROJECT_EDIT_MODEL` | Modeler, Admin |
| `PROJECT_DECIDE_RISK` | Reviewer, Admin |
| `PROJECT_MANAGE_MEMBERS` | Admin |
| `PROJECT_DELETE` | Admin |
