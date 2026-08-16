# Enterprise Adoption Guide

This guide explains how to add HybridTM to an **already running** PHP application — whether it is a monolith, a microservice fleet, or a hybrid architecture — without disrupting ongoing development.

---

## Table of Contents

1. [Adoption Strategy](#adoption-strategy)
2. [Phase 1: Audit and Inventory](#phase-1-audit-and-inventory)
3. [Phase 2: Build the Baseline DSL Model](#phase-2-build-the-baseline-dsl-model)
4. [Phase 3: Add Attributes Incrementally](#phase-3-add-attributes-incrementally)
5. [Phase 4: CI/CD and Governance](#phase-4-cicd-and-governance)
6. [Patterns for Complex Cases](#patterns-for-complex-cases)
7. [Common Mistakes and How to Avoid Them](#common-mistakes-and-how-to-avoid-them)

---

## Adoption Strategy

**Core principle:** do not try to cover the entire system at once. Start with the most sensitive data flow and expand gradually.

### Three-Phase Approach

```
Phase 1 (1–2 weeks)      Phase 2 (2–4 weeks)      Phase 3 (continuous)
─────────────────────    ─────────────────────    ─────────────────────
Audit the system         Baseline DSL model       AI agent annotates
↓                        ↓                        new changes
Asset inventory          First threagile.yaml     ↓
↓                        ↓                        CI/CD blocks
Risk prioritisation      Manual annotation of     unannotated
                         critical paths            cross-service calls
```

---

## Phase 1: Audit and Inventory

Before writing any code, you need to understand what already exists.

### 1.1 Map the Components

Gather from the team or discover yourself:

- **Service list** (microservices, monolith, batch jobs, cron workers).
- **Database list** (RDBMS, NoSQL, key-value stores, message queues).
- **External dependency list** (payment gateways, identity providers, third-party APIs).
- **Data inventory** (what is stored, what flows, classification by sensitivity).

Useful discovery questions:

```
For each service:
  - What protocol does it accept (HTTP, gRPC, AMQP, …)?
  - Which other services does it communicate with?
  - What data does it process?
  - Which team owns it?
  - Does it handle payment card data (PCI DSS) or personal data (GDPR)?

For each database:
  - Is encryption at-rest configured?
  - Who has access — technical users only, or humans too?
  - Are credentials stored in plaintext anywhere?
```

### 1.2 Prioritise by Risk

Not all components are equally important. Start with those that:

| Indicator | Why it matters |
|-----------|----------------|
| Store PII or payment data | Regulatory requirements (GDPR, PCI DSS) |
| Accept data from the internet | Maximum attack surface |
| Have no authentication between services | Lateral movement risk |
| Transmit credentials in plain text | Critical vulnerability |
| Have no encryption at-rest | Data exposure if a host is compromised |

Build a simple priority table:

```
Component       | PII | Internet | Auth | Priority
──────────────────────────────────────────────────
API Gateway     | yes | yes      | no   | CRITICAL
User Service    | yes | no       | yes  | HIGH
Order Service   | no  | no       | yes  | MEDIUM
Admin Panel     | yes | yes      | no   | CRITICAL
Batch Jobs      | no  | no       | no   | LOW
```

---

## Phase 2: Build the Baseline DSL Model

Install the package without touching production code:

```bash
composer require hybridtm/hybridtm
```

### 2.1 Start with "as-is"

Create `threat-model.php` that reflects the **current** state of the system, even if it is imperfect. Do not try to model the ideal target state — model reality.

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
$model->description         = 'Threat model for existing platform (as-is, Q1 2024)';
$model->author              = 'Security Champion, Backend Team';
$model->date                = date('Y-01-01');
$model->businessCriticality = BusinessCriticality::Critical;

// ── Data Assets ───────────────────────────────────────────────────────────────
// Tip: start with 3–5 key DataAssets and add more detail over time.

$customerPii = new DataAsset('customer-pii', 'Customer PII');
$customerPii->description     = 'Name, email, phone, address (GDPR sensitive)';
$customerPii->confidentiality = Confidentiality::Confidential;
$customerPii->integrity       = Integrity::Important;
$customerPii->availability    = Availability::Important;
$customerPii->origin          = DataOrigin::UserInput;
$customerPii->quantity        = Quantity::VeryMany;
$model->addDataAsset($customerPii);

$orderData = new DataAsset('order-data', 'Order & Transaction Data');
$orderData->description     = 'Orders, statuses, payment history';
$orderData->confidentiality = Confidentiality::Internal;
$orderData->integrity       = Integrity::Critical;
$orderData->availability    = Availability::Critical;
$orderData->origin          = DataOrigin::UserInput;
$orderData->quantity        = Quantity::VeryMany;
$model->addDataAsset($orderData);

$internalConfig = new DataAsset('internal-config', 'Internal Config & Secrets');
$internalConfig->description     = 'DB credentials, API keys, environment variables';
$internalConfig->confidentiality = Confidentiality::StrictlyConfidential;
$internalConfig->integrity       = Integrity::Critical;
$internalConfig->availability    = Availability::Critical;
$internalConfig->origin          = DataOrigin::InHouse;
$internalConfig->quantity        = Quantity::VeryFew;
$model->addDataAsset($internalConfig);

// ── Technical Assets ──────────────────────────────────────────────────────────
//
// IMPORTANT: if a legacy service is poorly understood, use conservative
// (higher-severity) CIA values. It is better to over-estimate risk than to
// miss a real one.

$legacyMonolith = new TechnicalAsset('monolith', 'Legacy PHP Monolith');
$legacyMonolith->type                 = AssetType::Process;
$legacyMonolith->technology           = Technology::WebApplication;
$legacyMonolith->size                 = Size::System;
$legacyMonolith->machine              = Machine::Virtual;  // bare-metal? → Machine::Physical
$legacyMonolith->customDevelopedParts = true;
$legacyMonolith->confidentiality      = Confidentiality::Confidential;
$legacyMonolith->integrity            = Integrity::Critical;
$legacyMonolith->availability         = Availability::Critical;
$legacyMonolith->owner                = 'Platform Team';
// If unsure what data the component handles, list everything
$legacyMonolith->dataAssetsProcessed  = ['customer-pii', 'order-data'];
$model->addTechnicalAsset($legacyMonolith);

$mainDb = new TechnicalAsset('main-db', 'MySQL Production Database');
$mainDb->type             = AssetType::Datastore;
$mainDb->technology       = Technology::Database;
$mainDb->size             = Size::System;
$mainDb->machine          = Machine::Virtual;
// If encryption at-rest is not configured, explicitly set None.
// This will surface the risk in the Threagile report.
$mainDb->encryption       = Encryption::None;
$mainDb->confidentiality  = Confidentiality::StrictlyConfidential;
$mainDb->integrity        = Integrity::Critical;
$mainDb->availability     = Availability::Critical;
$mainDb->owner            = 'DBA Team';
$mainDb->dataAssetsStored = ['customer-pii', 'order-data'];
$model->addTechnicalAsset($mainDb);

$externalPayment = new TechnicalAsset('payment-gateway', 'External Payment Gateway');
$externalPayment->type          = AssetType::ExternalEntity;
$externalPayment->technology    = Technology::WebServiceRest;
$externalPayment->internet      = true;
$externalPayment->machine       = Machine::Virtual;
$externalPayment->size          = Size::System;
$externalPayment->confidentiality = Confidentiality::StrictlyConfidential;
$externalPayment->integrity     = Integrity::MissionCritical;
$externalPayment->availability  = Availability::Critical;
$model->addTechnicalAsset($externalPayment);

// ── Trust Boundaries ──────────────────────────────────────────────────────────
// If the network topology is unknown, use broad categories.

$internet = new TrustBoundary('internet', 'Internet', TrustBoundaryType::NetworkDedicatedHoster);
$internet->addAssets('payment-gateway');
$model->addTrustBoundary($internet);

$datacenter = new TrustBoundary('dc', 'Data Centre', TrustBoundaryType::NetworkOnPrem);
$datacenter->description = 'Own data centre or dedicated hosting provider';
$datacenter->addAssets('monolith', 'main-db');
$model->addTrustBoundary($datacenter);

return $model;
```

### 2.2 Verify the First Run

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

Open `threagile-output/risks.json`. At this stage you will see risks from the **DSL alone** — without any code annotations. This is already useful: Threagile will identify architectural problems such as unencrypted databases, missing inter-service authentication, and so on.

---

## Phase 3: Add Attributes Incrementally

### 3.1 Start with the Most Critical Paths

You do not need to annotate the entire codebase at once. Begin with methods that:
- Accept data from the internet.
- Transfer PII or payment data.
- Handle authentication or authorisation.

### 3.2 Technique: Grep-Driven Discovery

Find all outbound HTTP calls in the codebase:

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

Every matching method is a candidate for `#[DataFlow]`.

### 3.3 Annotation Pattern — Monolith

A monolith typically contains mixed logic. Split annotations by semantic role:

```php
<?php
// src/Service/PaymentService.php
// This class already exists in production.
// We only add attributes — the implementation code is untouched.

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

#[AssetId('monolith')]
class PaymentService
{
    private \GuzzleHttp\Client $http;

    /**
     * Calls the external payment gateway.
     * Attributes reflect the real runtime behaviour of this method.
     */
    #[DataFlow(
        target: 'payment-gateway',
        protocol: Protocol::Https,
        authentication: Authentication::Token,       // Bearer token for Stripe/Braintree
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],                    // order amount and description
        readonly: false,
    )]
    #[Mitigation(
        cwe: 'CWE-312',
        description: 'Raw card numbers never reach our servers; tokenisation done client-side via Stripe.js',
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

### 3.4 Annotation Pattern — Microservice

For a microservice with a well-defined role:

```php
<?php
// services/order-service/src/Api/UserApiClient.php
// Client that lives in order-service and calls user-service

use HybridTM\Attributes\{AssetId, DataFlow};
use HybridTM\Enums\{Authentication, Authorization, Protocol};

#[AssetId('order-service')]
class UserApiClient
{
    #[DataFlow(
        target: 'user-service',         // must be a TechnicalAsset in the DSL
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['customer-pii'], // user profile for order display
        readonly: true,
    )]
    public function getUserProfile(string $userId): array
    {
        // Guzzle / Symfony HttpClient call
    }
}
```

### 3.5 Annotation Pattern — Repository (Database Layer)

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

    // INSERT / UPDATE — not readonly
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
        description: 'Doctrine ORM parameterised queries; no raw SQL with user input',
        status: MitigationStatus::Mitigated,
    )]
    public function save(array $user): int
    {
        // Doctrine / PDO
    }

    // GDPR: right to erasure
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii'],
    )]
    public function deleteById(int $id): void
    {
        // Hard delete for GDPR compliance
    }
}
```

### 3.6 Annotation Pattern — Async Workers and Message Queues

```php
<?php
// src/Consumer/OrderProcessedConsumer.php

use HybridTM\Attributes\{AssetId, DataFlow};
use HybridTM\Enums\{Authentication, Authorization, Protocol};

#[AssetId('order-service')]
class OrderProcessedConsumer
{
    // Worker reads from a queue — this is also a DataFlow
    #[DataFlow(
        target: 'message-queue',        // RabbitMQ / SQS — add to the DSL
        protocol: Protocol::Jms,        // AMQP / JMS
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    public function __invoke(OrderProcessedMessage $message): void
    {
        // process the event
    }

    // Worker publishes result to another queue / service
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

## Phase 4: CI/CD and Governance

### 4.1 Gradual CI Enablement

Do not block the pipeline immediately. Use **warnings** until sufficient coverage is reached:

```yaml
# .github/workflows/threat-model.yml
- name: Compile threat model
  run: |
    php bin/hybridtm compile \
      --infra=threat-model.php \
      --source=src/ \
      --out=threagile.yaml
  # Not blocking yet — only warnings
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

Once critical services are covered, remove `continue-on-error: true`.

### 4.2 Ownership Model for Enterprise

In large teams it is important to define who owns each component in the model:

```php
// threat-model.php — set owner on every TechnicalAsset
$paymentService->owner = 'payments-team@company.com';
$authService->owner    = 'security-team@company.com';
$userService->owner    = 'user-platform-team@company.com';
```

### 4.3 Risk Tracking

When Threagile identifies a risk, it can be marked as accepted, deferred, or mitigated. The recommended enterprise approach is to commit `threagile.yaml` to git and edit the `risk_tracking` block directly:

```yaml
# threagile.yaml — edited manually or via script
risk_tracking:
  sql-injection@main-db:
    status: mitigated
    justification: "All queries via Doctrine ORM with parameterised statements. Audited Q4 2023."
    date: '2024-01-15'
    ticket: "SEC-142"

  missing-authentication@internal-api:
    status: accepted
    justification: "Internal API accessible only from the VPC private subnet. Network-level isolation is sufficient given the current threat model."
    date: '2024-01-15'
    ticket: "SEC-98"
```

---

## Patterns for Complex Cases

### Monorepo with Multiple Services

```
monorepo/
├── threat-model.php          ← single DSL model for all services
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
	    --source=services/ \     # scans all services recursively
	    --out=threagile.yaml
```

### Multiple Teams — Separate Partial Models

If each team wants to own their slice of the model:

```php
// threat-model.php — aggregates separate team files
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\BusinessCriticality;

// Each team maintains their own asset file
$userAssets    = require __DIR__ . '/threat-models/user-service.php';
$orderAssets   = require __DIR__ . '/threat-models/order-service.php';
$paymentAssets = require __DIR__ . '/threat-models/payment-service.php';

$model = new ThreatModel('Full Platform');
$model->businessCriticality = BusinessCriticality::Critical;

foreach ($userAssets    as $asset) { $model->addTechnicalAsset($asset); }
foreach ($orderAssets   as $asset) { $model->addTechnicalAsset($asset); }
foreach ($paymentAssets as $asset) { $model->addTechnicalAsset($asset); }

return $model;
```

```php
// threat-models/user-service.php — only this team's TechnicalAssets
// Returns an array of assets, not a ThreatModel
return [
    (function () {
        $svc = new \HybridTM\DSL\TechnicalAsset('user-service', 'User Service');
        $svc->owner = 'user-team@company.com';
        // ...
        return $svc;
    })(),
];
```

### Legacy Code Without Strict Typing (PHP 7.x)

If part of the codebase is written in PHP < 8.0, attributes cannot be placed directly in those files. Create separate **mapping files** instead:

```php
<?php
// threat-models/annotations/LegacyPaymentServiceAnnotations.php
// This file lives alongside the model, not with the legacy code.
// It is ONLY for HybridTM scanning — never instantiated at runtime.

declare(strict_types=1);
namespace ThreatAnnotations;

use HybridTM\Attributes\{AssetId, DataFlow};
use HybridTM\Enums\{Authentication, Protocol};

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

Place the mapping files inside `src/` (or a subdirectory of it) so the scanner picks them up.

### Integrating with Third-Party Systems (SSO, ESB, ERP)

```php
// threat-model.php

// SAP ERP — external system, communication via ESB
$sap = new TechnicalAsset('sap-erp', 'SAP ERP');
$sap->type        = AssetType::ExternalEntity;
$sap->technology  = Technology::Erp;
$sap->internet    = false;
$sap->machine     = Machine::Physical;
$sap->size        = Size::System;
$sap->confidentiality = Confidentiality::Restricted;
$sap->integrity   = Integrity::Critical;
$sap->availability = Availability::Critical;
$model->addTechnicalAsset($sap);

$esb = new TechnicalAsset('esb', 'Enterprise Service Bus (MuleSoft)');
$esb->type        = AssetType::Process;
$esb->technology  = Technology::MessageQueue;
$esb->machine     = Machine::Virtual;
$esb->size        = Size::System;
$esb->customDevelopedParts = false;
$model->addTechnicalAsset($esb);

// Corporate SSO / LDAP
$ldap = new TechnicalAsset('ldap', 'Corporate LDAP / Active Directory');
$ldap->type       = AssetType::Datastore;
$ldap->technology = Technology::LdapServer;
$ldap->machine    = Machine::Virtual;
$ldap->confidentiality = Confidentiality::StrictlyConfidential;
$ldap->dataAssetsStored = ['internal-config']; // credentials
$model->addTechnicalAsset($ldap);
```

### Kubernetes / Cloud-Native Environments

```php
// Kubernetes namespace trust boundary
$k8sNamespace = new TrustBoundary(
    'k8s-prod',
    'Kubernetes Production Namespace',
    TrustBoundaryType::NetworkPolicyNamespaceIsolation,
);
$k8sNamespace->description = 'K8s namespace with NetworkPolicy; access only via ingress';
$k8sNamespace->addAssets('web-app', 'api-service', 'auth-service');
$model->addTrustBoundary($k8sNamespace);

// Ingress / WAF layer outside the namespace
$ingress = new TrustBoundary(
    'ingress',
    'Ingress / WAF Layer',
    TrustBoundaryType::NetworkCloudSecurityGroup,
);
$ingress->addAssets('api-gateway');
$model->addTrustBoundary($ingress);
```

---

## Common Mistakes and How to Avoid Them

### ❌ Creating a Single "UserData" DataAsset for Everything

```php
// BAD: everything lumped together
$userData = new DataAsset('user-data', 'User Data');
// Threagile cannot correctly score risk for mixed data types.

// GOOD: split by sensitivity level
$userPii         = new DataAsset('user-pii', 'User PII (name, email)');
$userCredentials = new DataAsset('user-credentials', 'Password Hashes');
$userPreferences = new DataAsset('user-preferences', 'Non-sensitive Preferences');
```

### ❌ Omitting `encryption` on Datastores

```php
// BAD: leaving the default (None) without acknowledging it
$db = new TechnicalAsset('db', 'Database');

// GOOD: explicitly state the real situation
$db->encryption = Encryption::None; // if not configured — be honest
// OR
$db->encryption = Encryption::DataWithSymmetricSharedKey; // if configured
$db->justificationCiaRating = 'Encrypted via AWS RDS at-rest encryption with KMS';
```

### ❌ Placing `#[AssetId]` on a Base Class or Trait

```php
// BAD: the attribute is inherited by all subclasses
#[AssetId('web-app')]
abstract class AbstractController {}

// GOOD: place the attribute on each concrete class
#[AssetId('web-app')]
class UserController extends AbstractController {}

#[AssetId('admin-panel')]  // different asset!
class AdminController extends AbstractController {}
```

### ❌ Annotating Internal Helper Methods

```php
// BAD: a private helper within the same service is not a cross-service call
#[AssetId('web-app')]
class UserController
{
    #[DataFlow(target: 'web-app', ...)] // web-app → web-app? Makes no sense.
    private function formatResponse(array $data): array {}
}

// GOOD: only annotate methods that cross a service boundary
#[AssetId('web-app')]
class UserController
{
    #[DataFlow(target: 'user-db', ...)] // web-app → user-db ✓
    public function getUser(int $id): array {}
}
```

### ❌ Referencing a Non-Existent Asset ID

```bash
# The compiler will report:
# [DataFlow@UserController::save] Unknown target asset 'users-database'.
# Add it to your threat model DSL file.

# Solution: the ID in the attribute must exactly match the ID in the DSL
$model->addTechnicalAsset(new TechnicalAsset('user-db', 'User Database'));
#                                              ^^^^^^^^
#[DataFlow(target: 'user-db', ...)]
#                   ^^^^^^^^
```

### ❌ Ignoring Compiler Warnings

```bash
php bin/hybridtm compile ... 2>&1 | grep -E "WARNING|ERROR"

# A WARNING means the DataFlow will not appear in the YAML.
# Always resolve warnings before committing.
```
