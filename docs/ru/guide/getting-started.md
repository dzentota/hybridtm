# Быстрый старт

## Только библиотека

Если нужен только rule engine и DSL, без API/Studio:

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
```

Это весь конвейер целиком: DSL → Rule Engine → находки, одной командой,
без базы данных и сервера. Что класть в `--kb` — см. [Наполнение базы
знаний](/ru/guide/kb-authoring).

## Studio (API + редактор-холст)

Studio добавляет персистентность, мультитенантность, RBAC, workflow
согласования модели и визуальный холст поверх той же библиотеки.

### Запуск локально

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

Откройте dev-сервер Studio, войдите под только что созданным аккаунтом
и перетащите компонент из палитры на холст. **Запустить анализ**
вызывает тот же Rule Engine, что и CLI — находки появляются вместе с
трассировкой правила (**Почему это сработало?**), объясняющей, какие
именно условия совпали.

### Основной цикл

1. Создайте проект, затем версию модели внутри него (через холст, либо
   `POST /api/model_versions` с каноническим JSON в `data`).
2. `POST /model-versions/{id}/analyze` — синхронный быстрый анализ без
   сохранения результата. Это путь «проверка по мере редактирования».
3. `POST /model-versions/{id}/analyze/deep` — асинхронный анализ на
   основе Threagile; опрашивайте или подпишитесь на `GET
   /deep-analysis-results/{id}(/events)`.
4. `GET /model-versions/{id}/findings` — тот же быстрый анализ,
   объединённый с зафиксированными решениями по рискам
   (`RiskDecisionRecord`: принять/митигировать/ложное
   срабатывание/отложить).
5. Когда готово: `submit-for-review` → `approve` (блокируется
   [policy-as-code](/ru/guide/api-reference#workflow-model-versions),
   если есть нарушение) → версия становится неизменяемой.

Полный список эндпоинтов — в [Справочнике API](/ru/guide/api-reference).
