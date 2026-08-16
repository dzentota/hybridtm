# Новый проект с нуля

Это руководство описывает, как встроить HybridTM в PHP-приложение **с первого дня** — ещё до того, как написана основная бизнес-логика.

---

## Оглавление

1. [Концепция](#концепция)
2. [Установка](#установка)
3. [Структура файлов](#структура-файлов)
4. [Шаг 1: Спроектировать инфраструктуру в DSL](#шаг-1-спроектировать-инфраструктуру-в-dsl)
5. [Шаг 2: Аннотировать сервисы атрибутами](#шаг-2-аннотировать-сервисы-атрибутами)
6. [Шаг 3: Скомпилировать и запустить Threagile](#шаг-3-скомпилировать-и-запустить-threagile)
7. [Шаг 4: Настроить CI/CD](#шаг-4-настроить-cicd)
8. [Шаг 5: Подключить AI-агента](#шаг-5-подключить-ai-агента)
9. [Полный пример — e-commerce сервис](#полный-пример--e-commerce-сервис)
10. [Рабочий процесс команды](#рабочий-процесс-команды)

---

## Концепция

HybridTM строится вокруг одного принципа: **угрозовая модель живёт рядом с кодом, а не отдельно от него**.

Две части, которые нужно поддерживать:

| Часть | Файл | Кто редактирует | Когда |
|-------|------|-----------------|-------|
| Инфраструктурный DSL | `threat-model.php` | Архитектор / лид | При добавлении нового сервиса или компонента |
| Атрибуты кода | `src/**/*.php` | AI-агент (Copilot, Cursor) | Автоматически при каждом PR |

---

## Установка

```bash
composer require hybridtm/hybridtm
```

Требования: PHP ≥ 8.2, Docker (для запуска Threagile).

---

## Структура файлов

Рекомендуемая раскладка нового проекта:

```
my-app/
├── src/
│   ├── Controller/
│   │   └── UserController.php       # аннотируется #[AssetId] и #[DataFlow]
│   ├── Service/
│   │   ├── AuthService.php
│   │   └── PaymentService.php
│   └── Repository/
│       └── UserRepository.php
├── threat-model.php                  # единственный DSL-файл
├── .github/
│   └── workflows/
│       └── threat-model.yml          # CI/CD pipeline
├── .copilot/
│   └── SKILL.md → symlink или копия SKILL.md из hybridtm
└── composer.json
```

---

## Шаг 1: Спроектировать инфраструктуру в DSL

Создайте `threat-model.php` в корне проекта. DSL описывает **что существует** в системе — активы, данные, границы доверия.

Правила:
- Каждый самостоятельный компонент — `TechnicalAsset`.
- Каждый тип данных, который передаётся или хранится — `DataAsset`.
- Группы компонентов по уровню доверия — `TrustBoundary`.
- Файл должен заканчиваться `return $model;`.

```php
<?php
// threat-model.php
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\{DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{
    AssetType, Authentication, Authorization, Availability,
    BusinessCriticality, Confidentiality, DataOrigin, Encryption,
    Integrity, Machine, Protocol, Quantity, Size, Technology, TrustBoundaryType
};

// ─── Метаданные модели ────────────────────────────────────────────────────────

$model = new ThreatModel('My E-Commerce App');
$model->description   = 'Угрозовая модель интернет-магазина';
$model->author        = 'Platform Security Team';
$model->date          = '2024-01-15';
$model->businessCriticality = BusinessCriticality::Critical;

// ─── DataAsset: типы данных ───────────────────────────────────────────────────

// Правило: один DataAsset = один смысловой класс данных.
// Не создавайте "UserData" для всего — разделяйте по чувствительности.

$customerPii = new DataAsset('customer-pii', 'Customer PII');
$customerPii->description      = 'Имя, email, адрес доставки';
$customerPii->confidentiality  = Confidentiality::Confidential;
$customerPii->integrity        = Integrity::Important;
$customerPii->availability     = Availability::Important;
$customerPii->origin           = DataOrigin::UserInput;
$customerPii->quantity         = Quantity::VeryMany;
$model->addDataAsset($customerPii);

$paymentData = new DataAsset('payment-data', 'Payment Card Data');
$paymentData->description      = 'Номер карты, срок, CVV (только транзитно — не хранится)';
$paymentData->confidentiality  = Confidentiality::StrictlyConfidential;
$paymentData->integrity        = Integrity::Critical;
$paymentData->availability     = Availability::Critical;
$paymentData->origin           = DataOrigin::UserInput;
$paymentData->quantity         = Quantity::Many;
$model->addDataAsset($paymentData);

$sessionToken = new DataAsset('session-token', 'Session Token');
$sessionToken->description     = 'JWT токен аутентификации';
$sessionToken->confidentiality = Confidentiality::StrictlyConfidential;
$sessionToken->integrity       = Integrity::Critical;
$sessionToken->availability    = Availability::Operational;
$sessionToken->origin          = DataOrigin::InHouse;
$sessionToken->quantity        = Quantity::VeryMany;
$model->addDataAsset($sessionToken);

$orderData = new DataAsset('order-data', 'Order Data');
$orderData->description        = 'Состав заказа, статус, история';
$orderData->confidentiality    = Confidentiality::Internal;
$orderData->integrity          = Integrity::Critical;
$orderData->availability       = Availability::Critical;
$orderData->origin             = DataOrigin::UserInput;
$orderData->quantity           = Quantity::VeryMany;
$model->addDataAsset($orderData);

// ─── TechnicalAsset: компоненты ──────────────────────────────────────────────

// Внешние пользователи и системы — ExternalEntity
$browser = new TechnicalAsset('browser', 'User Browser');
$browser->type               = AssetType::ExternalEntity;
$browser->technology         = Technology::Browser;
$browser->usedAsClientByHuman = true;
$browser->internet           = true;
$browser->machine            = Machine::Physical;
$browser->size               = Size::Component;
$browser->confidentiality    = Confidentiality::Public;
$browser->integrity          = Integrity::Operational;
$browser->availability       = Availability::Operational;
$model->addTechnicalAsset($browser);

$paymentProvider = new TechnicalAsset('payment-provider', 'Payment Gateway (Stripe)');
$paymentProvider->type       = AssetType::ExternalEntity;
$paymentProvider->technology = Technology::WebServiceRest;
$paymentProvider->internet   = true;
$paymentProvider->machine    = Machine::Virtual;
$paymentProvider->size       = Size::System;
$paymentProvider->confidentiality = Confidentiality::StrictlyConfidential;
$paymentProvider->integrity  = Integrity::MissionCritical;
$paymentProvider->availability = Availability::Critical;
$model->addTechnicalAsset($paymentProvider);

// Собственные сервисы
$webApp = new TechnicalAsset('web-app', 'Web Application (PHP/Symfony)');
$webApp->type                 = AssetType::Process;
$webApp->technology           = Technology::WebApplication;
$webApp->size                 = Size::Service;
$webApp->machine              = Machine::Container;
$webApp->customDevelopedParts = true;
$webApp->confidentiality      = Confidentiality::Restricted;
$webApp->integrity            = Integrity::Critical;
$webApp->availability         = Availability::Critical;
$webApp->owner                = 'Backend Team';
$model->addTechnicalAsset($webApp);

$orderService = new TechnicalAsset('order-service', 'Order Microservice');
$orderService->type                 = AssetType::Process;
$orderService->technology           = Technology::WebServiceRest;
$orderService->size                 = Size::Service;
$orderService->machine              = Machine::Container;
$orderService->customDevelopedParts = true;
$orderService->confidentiality      = Confidentiality::Internal;
$orderService->integrity            = Integrity::Critical;
$orderService->availability         = Availability::Critical;
$orderService->owner                = 'Orders Team';
$model->addTechnicalAsset($orderService);

$authService = new TechnicalAsset('auth-service', 'Auth Service');
$authService->type                 = AssetType::Process;
$authService->technology           = Technology::WebServiceRest;
$authService->size                 = Size::Service;
$authService->machine              = Machine::Container;
$authService->customDevelopedParts = true;
$authService->confidentiality      = Confidentiality::Confidential;
$authService->integrity            = Integrity::MissionCritical;
$authService->availability         = Availability::Critical;
$authService->owner                = 'Security Team';
$authService->dataAssetsProcessed  = ['session-token', 'customer-pii'];
$model->addTechnicalAsset($authService);

// Хранилища данных
$mainDb = new TechnicalAsset('main-db', 'Main PostgreSQL Database');
$mainDb->type               = AssetType::Datastore;
$mainDb->technology         = Technology::Database;
$mainDb->size               = Size::System;
$mainDb->machine            = Machine::Virtual;
$mainDb->encryption         = Encryption::DataWithSymmetricSharedKey;
$mainDb->confidentiality    = Confidentiality::StrictlyConfidential;
$mainDb->integrity          = Integrity::Critical;
$mainDb->availability       = Availability::Critical;
$mainDb->owner              = 'DBA Team';
$mainDb->dataAssetsStored   = ['customer-pii', 'order-data'];
$model->addTechnicalAsset($mainDb);

$redisCache = new TechnicalAsset('redis-cache', 'Redis Session Cache');
$redisCache->type             = AssetType::Datastore;
$redisCache->technology       = Technology::Database; // NoSQL
$redisCache->size             = Size::Component;
$redisCache->machine          = Machine::Virtual;
$redisCache->encryption       = Encryption::Transparent;
$redisCache->confidentiality  = Confidentiality::StrictlyConfidential;
$redisCache->integrity        = Integrity::Critical;
$redisCache->availability     = Availability::Critical;
$redisCache->owner            = 'Platform Team';
$redisCache->dataAssetsStored = ['session-token'];
$model->addTechnicalAsset($redisCache);

// ─── TrustBoundary: зоны доверия ─────────────────────────────────────────────

// Интернет — минимальный уровень доверия
$internet = new TrustBoundary('internet', 'Internet (Untrusted)', TrustBoundaryType::NetworkDedicatedHoster);
$internet->description = 'Публичная сеть: браузеры, мобильные клиенты, партнёрские системы';
$internet->addAssets('browser', 'payment-provider');
$model->addTrustBoundary($internet);

// DMZ / Edge — API Gateway, WAF
$dmz = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
$dmz->description = 'Публичная зона, защищённая WAF и API Gateway';
$dmz->addAssets('web-app');
$model->addTrustBoundary($dmz);

// Внутренняя VPC — сервисы без прямого доступа из интернета
$internalVpc = new TrustBoundary('internal-vpc', 'Internal VPC', TrustBoundaryType::NetworkCloudProvider);
$internalVpc->description = 'Изолированная приватная сеть, доступ только из DMZ';
$internalVpc->addAssets('order-service', 'auth-service');
$model->addTrustBoundary($internalVpc);

// Слой данных — самый высокий уровень защиты
$dataLayer = new TrustBoundary('data-layer', 'Data Layer', TrustBoundaryType::NetworkCloudSecurityGroup);
$dataLayer->description = 'Изолированный слой БД, доступ только из Internal VPC';
$dataLayer->addAssets('main-db', 'redis-cache');
$model->addTrustBoundary($dataLayer);

return $model;
```

---

## Шаг 2: Аннотировать сервисы атрибутами

Для каждого класса, который **инициирует** запросы к другим сервисам:

1. Добавьте `#[AssetId('asset-id')]` на уровне класса — ID должен совпадать с ID в DSL.
2. Добавьте `#[DataFlow(...)]` на каждый метод, который делает внешний вызов.
3. Опционально — `#[Mitigation(...)]` для задокументированных мер безопасности.

```php
<?php
// src/Controller/CheckoutController.php
declare(strict_types=1);
namespace App\Controller;

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation, ProcessesData};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['customer-pii', 'payment-data', 'session-token'])]
class CheckoutController
{
    // Вызов auth-service для проверки сессии
    #[DataFlow(
        target: 'auth-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['session-token'],
        dataReceived: ['session-token'],
    )]
    public function validateSession(string $token): bool
    {
        // ...
    }

    // Вызов order-service для создания заказа
    #[DataFlow(
        target: 'order-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data', 'customer-pii'],
        dataReceived: ['order-data'],
    )]
    #[Mitigation(
        cwe: 'CWE-20',
        description: 'Input validation via Symfony Validator before forwarding to order-service',
        status: MitigationStatus::Mitigated,
    )]
    public function placeOrder(array $cartItems, string $userId): string
    {
        // ...
    }

    // Вызов payment provider — самые чувствительные данные
    #[DataFlow(
        target: 'payment-provider',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['payment-data'],
        dataReceived: ['order-data'],
        vpn: false,
        ipFiltered: false,
    )]
    #[Mitigation(
        cwe: 'CWE-311',
        description: 'Payment data transmitted only via TLS 1.3, never logged',
        status: MitigationStatus::Mitigated,
    )]
    #[Mitigation(
        cwe: 'CWE-312',
        description: 'Raw card data never stored — only tokenized reference returned by Stripe',
        status: MitigationStatus::Mitigated,
    )]
    public function processPayment(array $paymentDetails, string $orderId): string
    {
        // ...
    }
}
```

```php
<?php
// src/Service/OrderService.php
declare(strict_types=1);
namespace App\Service;

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

#[AssetId('order-service')]
class OrderService
{
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data', 'customer-pii'],
        dataReceived: ['order-data'],
    )]
    #[Mitigation(
        cwe: 'CWE-89',
        description: 'All DB queries use PDO prepared statements',
        status: MitigationStatus::Mitigated,
    )]
    public function save(array $order): string
    {
        // ...
    }

    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    public function findByUser(string $userId): array
    {
        // ...
    }
}
```

---

## Шаг 3: Скомпилировать и запустить Threagile

```bash
# Скомпилировать DSL + атрибуты → threagile.yaml
php bin/hybridtm compile \
    --infra=threat-model.php \
    --source=src/ \
    --out=threagile.yaml

# Создать директорию для вывода
mkdir -p threagile-output

# Запустить анализ
docker run --rm \
    -v "$(pwd):/work" \
    threagile/threagile:latest \
    --model /work/threagile.yaml \
    --output /work/threagile-output
```

Результат в `threagile-output/`:

```
data-flow-diagram.pdf     ← DFD с границами доверия
report.pdf                ← Полный отчёт с рисками
risks.json                ← Машиночитаемые риски
risks.xlsx                ← Excel для code review / security review
```

---

## Шаг 4: Настроить CI/CD

Создайте `.github/workflows/threat-model.yml`:

```yaml
name: Threat Model

on:
  push:
    branches: [main]
  pull_request:
    paths:
      - 'src/**'
      - 'threat-model.php'

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'

      - name: Install dependencies
        run: composer install --no-dev --prefer-dist

      - name: Compile threat model
        run: |
          php bin/hybridtm compile \
            --infra=threat-model.php \
            --source=src/ \
            --out=threagile.yaml

      - name: Run Threagile analysis
        run: |
          mkdir -p threagile-output
          docker run --rm \
            -v "${{ github.workspace }}:/work" \
            threagile/threagile:latest \
            --model /work/threagile.yaml \
            --output /work/threagile-output

      - name: Upload threat model report
        uses: actions/upload-artifact@v4
        with:
          name: threat-model-${{ github.sha }}
          path: |
            threagile.yaml
            threagile-output/report.pdf
            threagile-output/risks.json

      # Опционально: упасть, если есть новые критические риски
      - name: Check for critical risks
        run: |
          CRITICAL=$(cat threagile-output/risks.json | python3 -c "
          import sys,json
          risks = json.load(sys.stdin)
          critical = [r for r in risks if r.get('severity') == 'critical']
          print(len(critical))
          ")
          echo "Critical risks found: $CRITICAL"
          # Раскомментируйте, чтобы блокировать PR при критических рисках:
          # [ "$CRITICAL" -eq 0 ] || exit 1
```

---

## Шаг 5: Подключить AI-агента

Скопируйте `SKILL.md` из пакета HybridTM в конфигурацию вашего AI-ассистента:

```bash
# Для GitHub Copilot (Workspace Instructions)
cp vendor/hybridtm/hybridtm/SKILL.md .github/copilot-instructions.md

# Для Cursor
cp vendor/hybridtm/hybridtm/SKILL.md .cursor/rules/hybridtm.mdc

# Для Claude Code (Agents)
cp vendor/hybridtm/hybridtm/SKILL.md CLAUDE.md
```

После этого AI-агент будет **автоматически** добавлять `#[DataFlow]` при написании кода, который пересекает границы сервисов.

**Проверка:** попросите AI написать метод, который вызывает внешний сервис. В сгенерированном коде должны появиться аннотации.

---

## Полный пример — e-commerce сервис

Полный рабочий пример доступен в директории `example/` пакета.

---

## Рабочий процесс команды

### День 0 (инициализация проекта)

1. Архитектор создаёт `threat-model.php` с начальным набором активов.
2. DevOps настраивает CI/CD пайплайн.
3. Тимлид добавляет `SKILL.md` в конфигурацию AI-агента.

### Каждый PR (разработчики)

- AI-агент автоматически добавляет `#[DataFlow]` на новые методы, пересекающие границы.
- Разработчик ревьюит атрибуты вместе с кодом (они видны в diff).
- Если добавлен новый сервис → разработчик добавляет `TechnicalAsset` в `threat-model.php`.

### Каждый релиз (тимлид / Security Champion)

- Просматривает `risks.json` из артефактов сборки.
- При необходимости добавляет `#[Mitigation]` или закрывает риски через `risk_tracking` в Threagile.
- Сохраняет `threagile.yaml` в git для diff между релизами.

### Ежеквартально (Security Review)

- Команда безопасности просматривает `report.pdf`.
- Обновляет `businessCriticality` и CIA-рейтинги по результатам аудита.
