# Внедрение в существующие энтерпрайз-приложения

Это руководство описывает, как добавить HybridTM в **уже работающее** PHP-приложение — монолит, микросервисы или гибридную архитектуру — не нарушая текущей разработки.

---

## Оглавление

1. [Стратегия внедрения](#стратегия-внедрения)
2. [Фаза 1: Аудит и инвентаризация](#фаза-1-аудит-и-инвентаризация)
3. [Фаза 2: Создание базовой DSL-модели](#фаза-2-создание-базовой-dsl-модели)
4. [Фаза 3: Добавление атрибутов](#фаза-3-добавление-атрибутов)
5. [Фаза 4: CI/CD и governance](#фаза-4-cicd-и-governance)
6. [Паттерны для сложных случаев](#паттерны-для-сложных-случаев)
7. [Типичные ошибки и как их избежать](#типичные-ошибки-и-как-их-избежать)

---

## Стратегия внедрения

**Главный принцип:** не пытайтесь покрыть всю систему сразу. Начните с самого чувствительного потока данных и расширяйте постепенно.

### Трёхфазный подход

```
Фаза 1 (1-2 недели)      Фаза 2 (2-4 недели)      Фаза 3 (continuous)
─────────────────────    ─────────────────────    ─────────────────────
Аудит системы            Базовая DSL-модель       AI-агент аннотирует
↓                        ↓                        новые изменения
Карта активов            Первый threagile.yaml    ↓
↓                        ↓                        CI/CD блокирует
Приоритизация            Ручная аннотация          неаннотированные
рисков                   критичных путей           cross-service вызовы
```

---

## Фаза 1: Аудит и инвентаризация

Прежде чем писать код — нужно понять, что уже есть в системе.

### 1.1 Составить карту компонентов

Запросите у команды или соберите самостоятельно:

- **Список сервисов** (микросервисы, монолит, batch jobs, cron).
- **Список баз данных** (RDBMS, NoSQL, key-value, очереди сообщений).
- **Список внешних зависимостей** (payment gateways, identity providers, 3rd-party APIs).
- **Список данных** (что хранится, что передаётся, классификация по чувствительности).

Шаблон вопросов:

```
Для каждого сервиса:
  - Какой протокол он принимает?
  - С какими другими сервисами взаимодействует?
  - Какие данные обрабатывает?
  - Кто им владеет (команда)?
  - Есть ли данные платёжных карт (PCI DSS) или персональные данные (GDPR)?

Для каждой БД:
  - Какое шифрование at-rest?
  - Кто имеет доступ (technical user vs. human)?
  - Хранятся ли credentials в plaintext?
```

### 1.2 Приоритизировать по риску

Не все компоненты одинаково важны. Начинайте с тех, где:

| Признак | Почему важно |
|---------|-------------|
| Хранятся PII / платёжные данные | Регуляторные требования (GDPR, PCI DSS) |
| Принимают данные из интернета | Поверхность атаки максимальна |
| Нет аутентификации между сервисами | Lateral movement риск |
| Передают credentials в открытом виде | Критическая уязвимость |
| Нет шифрования at-rest | Утечка данных при компрометации хоста |

Создайте простую таблицу приоритетов:

```
Компонент       | PII | Интернет | Auth | Приоритет
──────────────────────────────────────────────────
API Gateway     | да  | да       | нет  | CRITICAL
User Service    | да  | нет      | да   | HIGH
Order Service   | нет | нет      | да   | MEDIUM
Admin Panel     | да  | да       | нет  | CRITICAL
Batch Jobs      | нет | нет      | нет  | LOW
```

---

## Фаза 2: Создание базовой DSL-модели

Установите пакет без изменения production-кода:

```bash
composer require hybridtm/hybridtm
```

### 2.1 Начните с "как есть" (as-is)

Создайте `threat-model.php`, отражающий текущее состояние системы, даже если оно несовершенно. Не пытайтесь сразу описать идеальное состояние.

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

$model = new ThreatModel('Legacy E-Commerce Platform');
$model->description         = 'Угрозовая модель существующей платформы (as-is, Q1 2024)';
$model->author              = 'Security Champion, Backend Team';
$model->date                = date('Y-01-01');
$model->businessCriticality = BusinessCriticality::Critical;

// ─── Данные ───────────────────────────────────────────────────────────────────
// Совет: начните с 3-5 ключевых DataAsset, постепенно детализируйте

$customerPii = new DataAsset('customer-pii', 'Customer PII');
$customerPii->description     = 'Имя, email, телефон, адрес (GDPR sensitive)';
$customerPii->confidentiality = Confidentiality::Confidential;
$customerPii->integrity       = Integrity::Important;
$customerPii->availability    = Availability::Important;
$customerPii->origin          = DataOrigin::UserInput;
$customerPii->quantity        = Quantity::VeryMany;
$model->addDataAsset($customerPii);

$orderData = new DataAsset('order-data', 'Order & Transaction Data');
$orderData->description     = 'Заказы, статусы, история платежей';
$orderData->confidentiality = Confidentiality::Internal;
$orderData->integrity       = Integrity::Critical;
$orderData->availability    = Availability::Critical;
$orderData->origin          = DataOrigin::UserInput;
$orderData->quantity        = Quantity::VeryMany;
$model->addDataAsset($orderData);

$internalConfig = new DataAsset('internal-config', 'Internal Config & Secrets');
$internalConfig->description     = 'DB credentials, API keys, env variables';
$internalConfig->confidentiality = Confidentiality::StrictlyConfidential;
$internalConfig->integrity       = Integrity::Critical;
$internalConfig->availability    = Availability::Critical;
$internalConfig->origin          = DataOrigin::InHouse;
$internalConfig->quantity        = Quantity::VeryFew;
$model->addDataAsset($internalConfig);

// ─── Компоненты ───────────────────────────────────────────────────────────────

// ВАЖНО: Если сервис legacy и нет времени изучать детали —
// используйте консервативные (более "страшные") значения CIA:
// это лучше, чем занизить и пропустить реальный риск.

$legacyMonolith = new TechnicalAsset('monolith', 'Legacy PHP Monolith');
$legacyMonolith->type                 = AssetType::Process;
$legacyMonolith->technology           = Technology::WebApplication;
$legacyMonolith->size                 = Size::System;
$legacyMonolith->machine              = Machine::Virtual; // на bare-metal? → Machine::Physical
$legacyMonolith->customDevelopedParts = true;
$legacyMonolith->confidentiality      = Confidentiality::Confidential;
$legacyMonolith->integrity            = Integrity::Critical;
$legacyMonolith->availability         = Availability::Critical;
$legacyMonolith->owner                = 'Platform Team';
// Если не знаете, какие данные обрабатывает — добавьте всё
$legacyMonolith->dataAssetsProcessed  = ['customer-pii', 'order-data'];
$model->addTechnicalAsset($legacyMonolith);

$mainDb = new TechnicalAsset('main-db', 'MySQL Production Database');
$mainDb->type             = AssetType::Datastore;
$mainDb->technology       = Technology::Database;
$mainDb->size             = Size::System;
$mainDb->machine          = Machine::Virtual;
// Если шифрование at-rest не настроено — укажите None. Это покажет риск.
$mainDb->encryption       = Encryption::None;
$mainDb->confidentiality  = Confidentiality::StrictlyConfidential;
$mainDb->integrity        = Integrity::Critical;
$mainDb->availability     = Availability::Critical;
$mainDb->owner            = 'DBA Team';
$mainDb->dataAssetsStored = ['customer-pii', 'order-data'];
$model->addTechnicalAsset($mainDb);

$externalPayment = new TechnicalAsset('payment-gateway', 'External Payment Gateway');
$externalPayment->type         = AssetType::ExternalEntity;
$externalPayment->technology   = Technology::WebServiceRest;
$externalPayment->internet     = true;
$externalPayment->machine      = Machine::Virtual;
$externalPayment->size         = Size::System;
$externalPayment->confidentiality = Confidentiality::StrictlyConfidential;
$externalPayment->integrity    = Integrity::MissionCritical;
$externalPayment->availability = Availability::Critical;
$model->addTechnicalAsset($externalPayment);

// ─── Границы доверия ──────────────────────────────────────────────────────────

// Если топология сети неизвестна — используйте общие категории
$internet = new TrustBoundary('internet', 'Internet', TrustBoundaryType::NetworkDedicatedHoster);
$internet->addAssets('payment-gateway');
$model->addTrustBoundary($internet);

$datacenter = new TrustBoundary('dc', 'Data Center', TrustBoundaryType::NetworkOnPrem);
$datacenter->description = 'Собственный дата-центр / хостинг-провайдер';
$datacenter->addAssets('monolith', 'main-db');
$model->addTrustBoundary($datacenter);

return $model;
```

### 2.2 Верифицировать первый запуск

```bash
php bin/hybridtm compile \
    --infra=threat-model.php \
    --source=src/ \
    --out=threagile.yaml

mkdir -p threagile-output
docker run --rm \
    -v "$(pwd):/work" \
    threagile/threagile:latest \
    --model /work/threagile.yaml \
    --output /work/threagile-output
```

Посмотрите `threagile-output/risks.json`. На этом этапе вы увидите риски **только от DSL** — без аннотаций кода. Это уже полезно: Threagile выявит проблемы архитектуры (незашифрованные БД, отсутствие аутентификации между сервисами и т.д.).

---

## Фаза 3: Добавление атрибутов

### 3.1 Начните с самых критичных точек

Не нужно аннотировать сразу весь код. Начните с методов, которые:
- Принимают данные из интернета
- Передают PII или платёжные данные
- Работают с authentication/authorization

### 3.2 Техника: grep-driven discovery

Найдите все исходящие HTTP-вызовы в кодовой базе:

```bash
# cURL
grep -rn "curl_exec\|curl_init\|Curl(" src/ --include="*.php"

# Guzzle
grep -rn "->get(\|->post(\|->put(\|->request(" src/ --include="*.php"

# Symfony HttpClient
grep -rn "->request(\|HttpClient::" src/ --include="*.php"

# Doctrine / PDO (database calls)
grep -rn "->executeQuery\|->createQuery\|->prepare(" src/ --include="*.php"

# RabbitMQ / AMQP
grep -rn "->publish(\|->consume(" src/ --include="*.php"
```

Каждый найденный метод — кандидат на `#[DataFlow]`.

### 3.3 Паттерн аннотации монолита

Монолит обычно содержит смешанную логику. Разбейте по смысловым ролям:

```php
<?php
// src/Service/PaymentService.php

// Этот класс уже существует в production.
// Добавляем только атрибуты — код не трогаем.

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

// Если класс полностью относится к одному компоненту DSL:
#[AssetId('monolith')]
class PaymentService
{
    private GuzzleHttp\Client $http;

    /**
     * Обращается к внешнему платёжному шлюзу.
     * Атрибуты отражают реальное поведение метода.
     */
    #[DataFlow(
        target: 'payment-gateway',
        protocol: Protocol::Https,
        authentication: Authentication::Token,       // Bearer token для Stripe/Braintree
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],                   // сумма и описание заказа
        // payment-data не хранится в нашей системе — только проксируется
        readonly: false,
    )]
    #[Mitigation(
        cwe: 'CWE-312',
        description: 'Raw card numbers never reach our servers; tokenization done client-side via Stripe.js',
        status: MitigationStatus::Mitigated,
    )]
    public function charge(string $token, int $amountCents, string $currency): array
    {
        return $this->http->post('https://api.stripe.com/v1/charges', [
            'form_params' => [
                'source'   => $token,
                'amount'   => $amountCents,
                'currency' => $currency,
            ],
        ])->toArray();
    }
}
```

### 3.4 Паттерн аннотации микросервиса

Для микросервиса с чётко определённой ролью:

```php
<?php
// services/user-service/src/Api/UserApiClient.php
// Клиент, который вызывает этот сервис из другого сервиса

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

// Этот класс живёт в order-service и вызывает user-service
#[AssetId('order-service')]
class UserApiClient
{
    #[DataFlow(
        target: 'user-service',          // должен быть TechnicalAsset в DSL
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['customer-pii'],  // получаем профиль для отображения в заказе
        readonly: true,
    )]
    public function getUserProfile(string $userId): array
    {
        // Guzzle / Symfony HttpClient вызов
    }
}
```

### 3.5 Паттерн для репозиториев (Database layer)

```php
<?php
// src/Repository/UserRepository.php

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

#[AssetId('monolith')]
class UserRepository
{
    // SELECT queries
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['customer-pii'],
        readonly: true,
    )]
    public function findById(int $id): ?array
    {
        // Doctrine / PDO
    }

    // INSERT / UPDATE — не readonly
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii'],
        dataReceived: ['customer-pii'],
    )]
    #[Mitigation(
        cwe: 'CWE-89',
        description: 'Doctrine ORM parameterized queries, no raw SQL with user input',
        status: MitigationStatus::Mitigated,
    )]
    public function save(array $user): int
    {
        // Doctrine / PDO
    }

    // GDPR: право на удаление
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii'],
    )]
    public function deleteById(int $id): void
    {
        // Hard delete для GDPR compliance
    }
}
```

### 3.6 Асинхронные воркеры и очереди сообщений

```php
<?php
// src/Consumer/OrderProcessedConsumer.php

use HybridTM\Attributes\{AssetId, DataFlow};
use HybridTM\Enums\{Authentication, Authorization, Protocol};

#[AssetId('order-service')]
class OrderProcessedConsumer
{
    // Воркер читает из очереди — это тоже DataFlow
    #[DataFlow(
        target: 'message-queue',       // RabbitMQ / SQS — добавьте в DSL
        protocol: Protocol::Jms,       // AMQP / JMS
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    public function __invoke(OrderProcessedMessage $message): void
    {
        // обработка события
    }

    // Воркер публикует результат в другую очередь / сервис
    #[DataFlow(
        target: 'notification-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data', 'customer-pii'],
    )]
    private function notifyUser(array $order): void
    {
        // webhook / HTTP callback
    }
}
```

---

## Фаза 4: CI/CD и governance

### 4.1 Постепенное включение в CI

Не включайте strict-mode сразу. Используйте **предупреждения** до достижения нужного покрытия:

```yaml
# .github/workflows/threat-model.yml
- name: Compile threat model
  run: |
    php bin/hybridtm compile \
      --infra=threat-model.php \
      --source=src/ \
      --out=threagile.yaml
  # Пока не блокируем — только предупреждения
  continue-on-error: true

- name: Run Threagile
  run: |
    mkdir -p threagile-output
    docker run --rm \
      -v "${{ github.workspace }}:/work" \
      threagile/threagile:latest \
      --model /work/threagile.yaml \
      --output /work/threagile-output
  continue-on-error: true
```

После достижения покрытия критичных сервисов уберите `continue-on-error: true`.

### 4.2 Ownership модель для энтерпрайза

В больших командах важно определить, кто отвечает за каждый компонент модели:

```php
// threat-model.php — добавляйте owner на каждый TechnicalAsset
$paymentService->owner = 'payments-team@company.com';
$authService->owner    = 'security-team@company.com';
$userService->owner    = 'user-platform-team@company.com';
```

### 4.3 Трекинг рисков (Risk Tracking)

Когда Threagile находит риск, его можно пометить как принятый, отложенный или митигированный напрямую в `threat-model.php` через секцию `risk_tracking` в итоговом YAML. Рекомендуемый подход для энтерпрайза — сохранять `threagile.yaml` в git и редактировать `risk_tracking` прямо в нём:

```yaml
# threagile.yaml (редактируется вручную или через скрипт)
risk_tracking:
  sql-injection@main-db:
    status: mitigated
    justification: "All queries via Doctrine ORM with parameterized statements. Audited Q4 2023."
    date: '2024-01-15'
    ticket: "SEC-142"

  missing-authentication@internal-api:
    status: accepted
    justification: "Internal API accessible only from VPC private subnet. Network-level isolation is sufficient given current threat model."
    date: '2024-01-15'
    ticket: "SEC-98"
```

---

## Паттерны для сложных случаев

### Монорепозиторий с несколькими сервисами

```
monorepo/
├── threat-model.php          ← единая DSL-модель для всех сервисов
├── services/
│   ├── user-service/src/
│   ├── order-service/src/
│   └── payment-service/src/
└── Makefile
```

```bash
# Makefile
threat-model:
    php bin/hybridtm compile \
        --infra=threat-model.php \
        --source=services/ \   # сканирует все сервисы рекурсивно
        --out=threagile.yaml
```

### Несколько команд — несколько частичных моделей

Если каждая команда хочет управлять своим куском модели:

```php
// threat-model.php — агрегирует отдельные файлы
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\ThreatModel;

// Каждая команда поддерживает свой файл с активами
$userAssets    = require __DIR__ . '/threat-models/user-service.php';
$orderAssets   = require __DIR__ . '/threat-models/order-service.php';
$paymentAssets = require __DIR__ . '/threat-models/payment-service.php';

$model = new ThreatModel('Full Platform');
$model->businessCriticality = \HybridTM\Enums\BusinessCriticality::Critical;

// Мерж активов из всех подмоделей
foreach ($userAssets    as $asset) { $model->addTechnicalAsset($asset); }
foreach ($orderAssets   as $asset) { $model->addTechnicalAsset($asset); }
foreach ($paymentAssets as $asset) { $model->addTechnicalAsset($asset); }

return $model;
```

```php
// threat-models/user-service.php — только TechnicalAsset'ы этой команды
// Возвращает массив активов, не ThreatModel
return [
    (function () {
        $svc = new \HybridTM\DSL\TechnicalAsset('user-service', 'User Service');
        $svc->owner = 'user-team@company.com';
        // ...
        return $svc;
    })(),
];
```

### Легаси-код без строгой типизации (PHP 7.x)

Если часть кодовой базы написана на PHP < 8.0, атрибуты нельзя разместить непосредственно в этих файлах. Создайте отдельные **маппинговые файлы**:

```php
<?php
// threat-models/annotations/LegacyPaymentService.php
// Этот файл живёт рядом с моделью, не с legacy кодом

declare(strict_types=1);
namespace ThreatAnnotations;

use HybridTM\Attributes\{AssetId, DataFlow};
use HybridTM\Enums\{Authentication, Protocol};

/**
 * Аннотации для LegacyPaymentService из legacy-модуля.
 * Этот класс ТОЛЬКО для целей сканирования HybridTM — не используется в runtime.
 */
#[AssetId('monolith')]
class LegacyPaymentServiceAnnotations
{
    #[DataFlow(
        target: 'payment-gateway',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
    )]
    public function charge(): void {}
}
```

```bash
# Сканируйте оба источника: legacy src/ и папку с аннотациями
php bin/hybridtm compile \
    --infra=threat-model.php \
    --source=src/,threat-models/annotations/ \   # TODO: multi-source (roadmap)
    --out=threagile.yaml
```

> **Заметка:** поддержка нескольких `--source` путей — в roadmap. Пока обходной путь: положите маппинговые файлы в поддиректорию `src/`.

### Интеграция с третьими системами (SSO, ESB, ERP)

```php
// threat-model.php

// SAP ERP — внешняя система, коммуникация через ESB
$sap = new TechnicalAsset('sap-erp', 'SAP ERP');
$sap->type       = AssetType::ExternalEntity;
$sap->technology = Technology::Erp;
$sap->internet   = false;
$sap->machine    = Machine::Physical;
$sap->size       = Size::System;
$sap->confidentiality = Confidentiality::Restricted;
$sap->integrity  = Integrity::Critical;
$sap->availability = Availability::Critical;
$model->addTechnicalAsset($sap);

$esb = new TechnicalAsset('esb', 'Enterprise Service Bus (MuleSoft)');
$esb->type       = AssetType::Process;
$esb->technology = Technology::MessageQueue;
$esb->machine    = Machine::Virtual;
$esb->size       = Size::System;
$esb->customDevelopedParts = false;
$model->addTechnicalAsset($esb);

// SSO / LDAP
$ldap = new TechnicalAsset('ldap', 'Corporate LDAP / Active Directory');
$ldap->type       = AssetType::Datastore;
$ldap->technology = Technology::LdapServer;
$ldap->machine    = Machine::Virtual;
$ldap->confidentiality = Confidentiality::StrictlyConfidential;
$ldap->dataAssetsStored = ['internal-config']; // credentials
$model->addTechnicalAsset($ldap);
```

### Kubernetes / Cloud-native среды

```php
// trust-boundary для K8s namespace
$k8sNamespace = new TrustBoundary(
    'k8s-prod',
    'Kubernetes Production Namespace',
    TrustBoundaryType::NetworkPolicyNamespaceIsolation
);
$k8sNamespace->description = 'K8s namespace с NetworkPolicy, доступ только через ingress';
$k8sNamespace->addAssets('web-app', 'api-service', 'auth-service');
$model->addTrustBoundary($k8sNamespace);

// Ingress / WAF вне namespace
$ingress = new TrustBoundary(
    'ingress',
    'Ingress / WAF Layer',
    TrustBoundaryType::NetworkCloudSecurityGroup
);
$ingress->addAssets('api-gateway');
$model->addTrustBoundary($ingress);
```

---

## Типичные ошибки и как их избежать

### ❌ Создать один DataAsset "UserData" для всего

```php
// ПЛОХО: всё в одну кучу
$userData = new DataAsset('user-data', 'User Data');
// Threagile не может корректно оценить риск для смешанных данных

// ХОРОШО: разделяйте по чувствительности
$userPii         = new DataAsset('user-pii', 'User PII (name, email)');
$userCredentials = new DataAsset('user-credentials', 'Password Hashes');
$userPreferences = new DataAsset('user-preferences', 'Non-sensitive Preferences');
```

### ❌ Не указывать `encryption` для баз данных

```php
// ПЛОХО: оставить по умолчанию (None)
$db = new TechnicalAsset('db', 'Database');
// Threagile сгенерирует риск, но вы потеряете контекст

// ХОРОШО: явно указать реальное состояние
$db->encryption = Encryption::None; // если не настроено — честно указываем None
// ИЛИ
$db->encryption = Encryption::DataWithSymmetricSharedKey; // если настроено
$db->justificationCiaRating = 'Encrypted via AWS RDS encryption at rest with KMS';
```

### ❌ Добавить `#[AssetId]` на базовый класс / трейт

```php
// ПЛОХО: атрибут на AbstractController наследуется всеми контроллерами
#[AssetId('web-app')]
abstract class AbstractController { }

// ХОРОШО: атрибут на конкретный класс
#[AssetId('web-app')]
class UserController extends AbstractController { }

#[AssetId('admin-panel')]  // другой asset!
class AdminController extends AbstractController { }
```

### ❌ Аннотировать методы-хелперы внутри одного сервиса

```php
// ПЛОХО: private helper внутри того же класса — это не cross-service вызов
#[AssetId('web-app')]
class UserController
{
    #[DataFlow(target: 'web-app', ...)] // web-app → web-app? Не имеет смысла
    private function formatResponse(array $data): array { }
}

// ХОРОШО: аннотируйте только методы, пересекающие границу сервиса
#[AssetId('web-app')]
class UserController
{
    #[DataFlow(target: 'user-db', ...)] // web-app → user-db ✓
    public function getUser(int $id): array { }
}
```

### ❌ Указать несуществующий ID в `target`

```bash
# Компилятор покажет:
# [DataFlow@UserController::save] Unknown target asset 'users-database'.
# Add it to your threat model DSL file.

# Решение: ID в атрибуте должен совпадать с ID в DSL
$model->addTechnicalAsset(new TechnicalAsset('user-db', 'User Database'));
#                                              ^^^^^^^^^
#[DataFlow(target: 'user-db', ...)]
#                   ^^^^^^^^^
```

### ❌ Игнорировать предупреждения компилятора

```bash
php bin/hybridtm compile ... 2>&1 | grep -E "WARNING|ERROR"

# WARNING означает, что DataFlow не будет создан в YAML
# Всегда исправляйте предупреждения перед коммитом
```
