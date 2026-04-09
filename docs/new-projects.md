# New Projects Guide

This guide explains how to integrate HybridTM into a PHP application **from day one** — before most of the business logic is written.

---

## Table of Contents

1. [Philosophy](#philosophy)
2. [Installation](#installation)
3. [Recommended File Structure](#recommended-file-structure)
4. [Step 1: Design the Infrastructure DSL](#step-1-design-the-infrastructure-dsl)
5. [Step 2: Annotate Services with Attributes](#step-2-annotate-services-with-attributes)
6. [Step 3: Compile and Run Threagile](#step-3-compile-and-run-threagile)
7. [Step 4: Set Up CI/CD](#step-4-set-up-cicd)
8. [Step 5: Connect the AI Agent](#step-5-connect-the-ai-agent)
9. [Full Example — E-Commerce Service](#full-example--e-commerce-service)
10. [Team Workflow](#team-workflow)

---

## Philosophy

HybridTM is built around a single principle: **the threat model lives next to the code, not separately from it**.

There are two parts to maintain:

| Part | File | Who edits it | When |
|------|------|--------------|------|
| Infrastructure DSL | `threat-model.php` | Architect / Tech Lead | When a new service or component is added |
| Code attributes | `src/**/*.php` | AI agent (Copilot, Cursor) | Automatically on every PR |

The DSL describes **what exists** in the system; the attributes describe **what the code does**.

---

## Installation

```bash
composer require hybridtm/hybridtm
```

Requirements: PHP ≥ 8.2, Docker (for running Threagile).

---

## Optional Bootstrap: CLI Wizard

Instead of writing `threat-model.php` from scratch, you can scaffold it interactively:

```bash
php bin/hybridtm init --out=threat-model.php
```

The wizard collects:
- project metadata
- data assets
- technical assets
- trust boundaries
- communication links

It then generates a valid baseline DSL file you can refine in Step 1.

---

## Recommended File Structure

```
my-app/
├── src/
│   ├── Controller/
│   │   └── UserController.php       # annotated with #[AssetId] and #[DataFlow]
│   ├── Service/
│   │   ├── AuthService.php
│   │   └── PaymentService.php
│   └── Repository/
│       └── UserRepository.php
├── threat-model.php                  # the single DSL file
├── .github/
│   └── workflows/
│       └── threat-model.yml          # CI/CD pipeline
├── .copilot/
│   └── SKILL.md → symlink or copy of SKILL.md from hybridtm package
└── composer.json
```

---

## Step 1: Design the Infrastructure DSL

Create `threat-model.php` at the project root. The DSL declares **what exists** — assets, data types, and trust boundaries.

Rules:
- Every independent component gets its own `TechnicalAsset`.
- Every meaningful data type that flows or is stored gets a `DataAsset`.
- Groups of components at the same trust level belong in a `TrustBoundary`.
- The file must end with `return $model;`.

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

// ── Model metadata ────────────────────────────────────────────────────────────

$model = new ThreatModel('My E-Commerce App');
$model->description         = 'Threat model for an online retail platform';
$model->author              = 'Platform Security Team';
$model->date                = '2024-01-15';
$model->businessCriticality = BusinessCriticality::Critical;

// ── Data Assets ───────────────────────────────────────────────────────────────
// Rule: one DataAsset = one meaningful data class.
// Do not lump everything into "UserData" — split by sensitivity level.

$customerPii = new DataAsset('customer-pii', 'Customer PII');
$customerPii->description     = 'Name, email, shipping address';
$customerPii->confidentiality = Confidentiality::Confidential;
$customerPii->integrity       = Integrity::Important;
$customerPii->availability    = Availability::Important;
$customerPii->origin          = DataOrigin::UserInput;
$customerPii->quantity        = Quantity::VeryMany;
$model->addDataAsset($customerPii);

$paymentData = new DataAsset('payment-data', 'Payment Card Data');
$paymentData->description     = 'Card number, expiry, CVV — transit only, never stored';
$paymentData->confidentiality = Confidentiality::StrictlyConfidential;
$paymentData->integrity       = Integrity::Critical;
$paymentData->availability    = Availability::Critical;
$paymentData->origin          = DataOrigin::UserInput;
$paymentData->quantity        = Quantity::Many;
$model->addDataAsset($paymentData);

$sessionToken = new DataAsset('session-token', 'Session Token');
$sessionToken->description     = 'JWT authentication token';
$sessionToken->confidentiality = Confidentiality::StrictlyConfidential;
$sessionToken->integrity       = Integrity::Critical;
$sessionToken->availability    = Availability::Operational;
$sessionToken->origin          = DataOrigin::InHouse;
$sessionToken->quantity        = Quantity::VeryMany;
$model->addDataAsset($sessionToken);

$orderData = new DataAsset('order-data', 'Order Data');
$orderData->description     = 'Cart contents, order status, transaction history';
$orderData->confidentiality = Confidentiality::Internal;
$orderData->integrity       = Integrity::Critical;
$orderData->availability    = Availability::Critical;
$orderData->origin          = DataOrigin::UserInput;
$orderData->quantity        = Quantity::VeryMany;
$model->addDataAsset($orderData);

// ── Technical Assets ──────────────────────────────────────────────────────────

// External users and systems — ExternalEntity
$browser = new TechnicalAsset('browser', 'User Browser');
$browser->type                = AssetType::ExternalEntity;
$browser->technology          = Technology::Browser;
$browser->usedAsClientByHuman = true;
$browser->internet            = true;
$browser->machine             = Machine::Physical;
$browser->size                = Size::Component;
$browser->confidentiality     = Confidentiality::Public;
$browser->integrity           = Integrity::Operational;
$browser->availability        = Availability::Operational;
$model->addTechnicalAsset($browser);

$paymentProvider = new TechnicalAsset('payment-provider', 'Payment Gateway (Stripe)');
$paymentProvider->type        = AssetType::ExternalEntity;
$paymentProvider->technology  = Technology::WebServiceRest;
$paymentProvider->internet    = true;
$paymentProvider->machine     = Machine::Virtual;
$paymentProvider->size        = Size::System;
$paymentProvider->confidentiality = Confidentiality::StrictlyConfidential;
$paymentProvider->integrity   = Integrity::MissionCritical;
$paymentProvider->availability = Availability::Critical;
$model->addTechnicalAsset($paymentProvider);

// Internal services
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

// Data stores
$mainDb = new TechnicalAsset('main-db', 'Main PostgreSQL Database');
$mainDb->type             = AssetType::Datastore;
$mainDb->technology       = Technology::Database;
$mainDb->size             = Size::System;
$mainDb->machine          = Machine::Virtual;
$mainDb->encryption       = Encryption::DataWithSymmetricSharedKey;
$mainDb->confidentiality  = Confidentiality::StrictlyConfidential;
$mainDb->integrity        = Integrity::Critical;
$mainDb->availability     = Availability::Critical;
$mainDb->owner            = 'DBA Team';
$mainDb->dataAssetsStored = ['customer-pii', 'order-data'];
$model->addTechnicalAsset($mainDb);

$redisCache = new TechnicalAsset('redis-cache', 'Redis Session Cache');
$redisCache->type             = AssetType::Datastore;
$redisCache->technology       = Technology::Database;
$redisCache->size             = Size::Component;
$redisCache->machine          = Machine::Virtual;
$redisCache->encryption       = Encryption::Transparent;
$redisCache->confidentiality  = Confidentiality::StrictlyConfidential;
$redisCache->integrity        = Integrity::Critical;
$redisCache->availability     = Availability::Critical;
$redisCache->owner            = 'Platform Team';
$redisCache->dataAssetsStored = ['session-token'];
$model->addTechnicalAsset($redisCache);

// ── Trust Boundaries ──────────────────────────────────────────────────────────

// Internet — minimal trust level
$internet = new TrustBoundary('internet', 'Internet (Untrusted)', TrustBoundaryType::NetworkDedicatedHoster);
$internet->description = 'Public network: browsers, mobile clients, partner systems';
$internet->addAssets('browser', 'payment-provider');
$model->addTrustBoundary($internet);

// DMZ / Edge — API Gateway, WAF
$dmz = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
$dmz->description = 'Public-facing zone protected by WAF and API Gateway';
$dmz->addAssets('web-app');
$model->addTrustBoundary($dmz);

// Internal VPC — services without direct internet access
$internalVpc = new TrustBoundary('internal-vpc', 'Internal VPC', TrustBoundaryType::NetworkCloudProvider);
$internalVpc->description = 'Isolated private network, accessible only from the DMZ';
$internalVpc->addAssets('order-service', 'auth-service');
$model->addTrustBoundary($internalVpc);

// Data layer — highest protection level
$dataLayer = new TrustBoundary('data-layer', 'Data Layer', TrustBoundaryType::NetworkCloudSecurityGroup);
$dataLayer->description = 'Isolated data tier, accessible only from the Internal VPC';
$dataLayer->addAssets('main-db', 'redis-cache');
$model->addTrustBoundary($dataLayer);

return $model;
```

---

## Step 2: Annotate Services with Attributes

For every class that **initiates** requests to other services:

1. Add `#[AssetId('asset-id')]` at the class level — the ID must match the DSL.
2. Add `#[DataFlow(...)]` to every method that makes an external call.
3. Optionally add `#[Mitigation(...)]` for documented security controls.

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
    // Session validation against auth-service
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

    // Order placement via order-service
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
        description: 'Input validated via Symfony Validator before forwarding to order-service',
        status: MitigationStatus::Mitigated,
    )]
    public function placeOrder(array $cartItems, string $userId): string
    {
        // ...
    }

    // Payment — most sensitive data flow
    #[DataFlow(
        target: 'payment-provider',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['payment-data'],
        dataReceived: ['order-data'],
    )]
    #[Mitigation(
        cwe: 'CWE-311',
        description: 'Payment data transmitted only via TLS 1.3, never logged',
        status: MitigationStatus::Mitigated,
    )]
    #[Mitigation(
        cwe: 'CWE-312',
        description: 'Raw card data never reaches our servers — client-side tokenisation via Stripe.js',
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

## Step 3: Compile and Run Threagile

```bash
# Compile DSL + attributes → threagile.yaml
php bin/hybridtm compile \
    --infra=threat-model.php \
    --source=src/ \
    --out=threagile.yaml

# Create output directory (Threagile requires it to pre-exist)
mkdir -p threagile-output

# Run analysis
docker run --rm \
    -v "$(pwd):/work" \
    threagile/threagile:latest \
    --model /work/threagile.yaml \
    --output /work/threagile-output
```

Output in `threagile-output/`:

```
data-flow-diagram.pdf     ← DFD with trust boundaries
report.pdf                ← Full risk report
risks.json                ← Machine-readable risk findings
risks.xlsx                ← Excel spreadsheet for review
```

---

## Step 4: Set Up CI/CD

Create `.github/workflows/threat-model.yml`:

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

      # Optional: fail the build if new critical risks appear
      - name: Check for critical risks
        run: |
          CRITICAL=$(cat threagile-output/risks.json | python3 -c "
          import sys, json
          risks = json.load(sys.stdin)
          print(sum(1 for r in risks if r.get('severity') == 'critical'))
          ")
          echo "Critical risks found: $CRITICAL"
          # Uncomment to block PRs with critical risks:
          # [ "$CRITICAL" -eq 0 ] || exit 1
```

---

## Step 5: Connect the AI Agent

Copy `SKILL.md` from the HybridTM package into your AI assistant configuration:

```bash
# GitHub Copilot (Workspace Instructions)
cp vendor/hybridtm/hybridtm/SKILL.md .github/copilot-instructions.md

# Cursor
cp vendor/hybridtm/hybridtm/SKILL.md .cursor/rules/hybridtm.mdc

# Claude Code
cp vendor/hybridtm/hybridtm/SKILL.md CLAUDE.md
```

After this, the AI agent will **automatically** add `#[DataFlow]` whenever it writes code that crosses a service boundary.

**Verification:** ask the AI to write a method that calls an external service. The generated code should include the appropriate attributes.

---

## Full Example — E-Commerce Service

A complete working example is available in the `example/` directory of the package.

---

## Team Workflow

### Day 0 (project initialisation)

1. The architect creates `threat-model.php` with the initial set of assets.
2. DevOps sets up the CI/CD pipeline.
3. The tech lead adds `SKILL.md` to the AI agent configuration.

### Every PR (developers)

- The AI agent automatically adds `#[DataFlow]` to new methods that cross service boundaries.
- The developer reviews the attributes alongside the code — they appear in the diff.
- If a new service is introduced, the developer adds its `TechnicalAsset` to `threat-model.php`.

### Every release (Tech Lead / Security Champion)

- Review `risks.json` from the build artefacts.
- Add `#[Mitigation]` where appropriate, or close risks via `risk_tracking` in Threagile.
- Commit `threagile.yaml` to git for diff comparison between releases.

### Quarterly (Security Review)

- The security team reviews `report.pdf`.
- Update `businessCriticality` and CIA ratings based on audit findings.
