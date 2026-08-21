# Getting Started

## Library only

If all you need is the rule engine and DSL, without the API/Studio:

```bash
composer require hybridtm/hybridtm
```

```php
<?php
require 'vendor/autoload.php';

use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TechnicalAsset;

$model = new ThreatModel('My App');
$db = new TechnicalAsset('db');
$db->traits = ['datastore', 'sql_engine'];
$db->properties->set('encryption_at_rest', false);
$model->addTechnicalAsset($db);

return $model;
```

```bash
php bin/hybridtm analyze --infra=threat-model.php --kb=path/to/kb --format=table

# With code mitigations + Abuser Story coverage gate:
php bin/hybridtm analyze \
    --infra=threat-model.php \
    --source=src/ \
    --kb=path/to/kb \
    --fail-on-uncovered-stories
```

This is the whole pipeline: DSL → Rule Engine → findings (and optional story coverage), in one
command, no database, no server. See [Knowledge Base
Authoring](/en/guide/kb-authoring) for what goes in `--kb`, and [Abuser
Stories](/en/guide/abuser-stories) for attacker-shaped acceptance criteria.

## Studio (API + canvas editor)

Studio adds persistence, multi-tenancy, RBAC, a model approval
workflow, and a visual canvas on top of the same library.

### Run it locally

```bash
docker compose up -d          # Postgres + Redis
cd apps/api
composer install
php bin/console doctrine:migrations:migrate --no-interaction
php bin/console app:create-user you@example.com yourpassword --tenant=acme --role=ROLE_ADMIN
php -S 127.0.0.1:8000 -t public
```

```bash
cd apps/studio
npm install
npm run dev
```

Open the Studio dev server, sign in with the account you just created,
and drag a component from the palette onto the canvas. **Run
analysis** calls the same Rule Engine the CLI does — findings appear
with a rule trace (**Why did this fire?**). Use the **Stories** tab to
author Abuser Stories, link actors/assets/threats, and see coverage
badges from `storyCoverage`.

### The core loop

1. Create a project, then a model version under it (a canvas, or `POST
   /api/model_versions` with a canonical-JSON `data` payload).
2. `POST /model-versions/{id}/analyze` — synchronous, fast, no
   persistence of the result. This is the "check as you edit" path
   (response may include `storyCoverage` when the model has abuse cases).
3. `POST /model-versions/{id}/analyze/deep` — asynchronous,
   Threagile-backed; poll or stream `GET
   /deep-analysis-results/{id}(/events)`.
4. `GET /model-versions/{id}/findings` — the same fast analysis,
   joined with any recorded risk decisions
   (`RiskDecisionRecord`, accept/mitigate/false-positive/defer).
5. When ready: `submit-for-review` → `approve` (blocked by
   [policy-as-code](/en/guide/api-reference#workflow-model-versions)
   if a violation exists) → the version becomes immutable.

See the [API Reference](/en/guide/api-reference) for the full endpoint
list.
