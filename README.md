# HybridTM

**HybridTM** is a PHP threat-modeling compiler that generates [Threagile](https://threagile.io)-compatible YAML from two sources:

- A **PHP DSL file** that declares the system infrastructure (assets, trust boundaries, data types).
- **PHP 8 attributes** (`#[DataFlow]`, `#[Mitigation]`, etc.) placed directly in application source code.

The compiler statically analyses the code (no execution) and merges both inputs into a single Threagile YAML file ready for risk analysis.

---

## Installation

```bash
composer require hybridtm/hybridtm
```

Requirements: PHP ≥ 8.2

---

## Quick Start

### 1. Write an infrastructure DSL file

```php
<?php // threat-model.php
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\{DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Authentication, Authorization, Availability,
    BusinessCriticality, Confidentiality, DataOrigin, Encryption,
    Integrity, Machine, Protocol, Size, Technology, TrustBoundaryType};

$model = new ThreatModel('My Service');
$model->businessCriticality = BusinessCriticality::Critical;

$secret = new DataAsset('api-key', 'API Key');
$secret->confidentiality = Confidentiality::StrictlyConfidential;
$model->addDataAsset($secret);

$api = new TechnicalAsset('api', 'REST API');
$api->type = AssetType::Process;
$api->technology = Technology::WebServiceRest;
$api->machine = Machine::Container;
$model->addTechnicalAsset($api);

$db = new TechnicalAsset('db', 'Database');
$db->type = AssetType::Datastore;
$db->technology = Technology::Database;
$db->dataAssetsStored = ['api-key'];
$model->addTechnicalAsset($db);

$vpc = new TrustBoundary('vpc', 'VPC', TrustBoundaryType::NetworkCloudProvider);
$vpc->addAssets('api', 'db');
$model->addTrustBoundary($vpc);

return $model;
```

### 2. Annotate your code

```php
<?php
namespace App;

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation};
use HybridTM\Enums\{Authentication, Authorization, Protocol};

#[AssetId('api')]
class ApiController
{
    #[DataFlow(
        target: 'db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['api-key'],
        dataReceived: ['api-key'],
    )]
    #[Mitigation('CWE-312', 'Secrets encrypted at rest')]
    public function getSecret(string $key): string { ... }
}
```

### 3. Compile

```bash
php bin/hybridtm compile \
    --infra=threat-model.php \
    --source=src/ \
    --out=threagile.yaml
```

---

## The Two-Part Model

| Part | File | Purpose |
|------|------|---------|
| Infrastructure DSL | `threat-model.php` | Declares assets, trust zones, data types |
| Code Attributes | `src/**/*.php` | Annotates real flows, mitigations, data usage |

The DSL describes the **architecture**; the attributes describe the **behaviour**.

---

## Command Reference

```
php bin/hybridtm compile [options]

Options:
  --infra=PATH      Path to the infrastructure DSL file  [default: threat-model.php]
  --source=DIR      Source directory to scan for attributes  [default: src/]
  --out=PATH        Output path for Threagile YAML  [default: threagile.yaml]
```

---

## Available Attributes

| Attribute | Target | Description |
|-----------|--------|-------------|
| `#[AssetId(string $id)]` | Class | Maps class to a DSL TechnicalAsset |
| `#[DataFlow(target, protocol, ...)]` | Method/Function | Declares a communication link |
| `#[Mitigation(cwe, description, status)]` | Class/Method/Function | Records a security control |
| `#[ProcessesData(dataAssets: [...])]` | Class/Method | Declares data asset processing |

---

## Example Output

```yaml
threagile_version: 1.0.0
title: My Service
date: '2024-01-15'
author:
  name: Security Team
business_criticality: critical
data_assets:
  api-key:
    id: api-key
    confidentiality: strictly-confidential
    ...
technical_assets:
  api:
    id: api
    type: process
    technology: web-service-rest
    communication_links:
      api-to-db:
        target: db
        protocol: jdbc-encrypted
        data_assets_sent: [api-key]
        data_assets_received: [api-key]
        ...
trust_boundaries:
  vpc:
    type: network-cloud-provider
    technical_assets_inside: [api, db]
```

---

## Project Structure

```
bin/
  hybridtm                  CLI entry point
src/
  Attributes/               PHP 8 attribute classes
    AssetId.php
    DataFlow.php
    Mitigation.php
    ProcessesData.php
  Compiler/                 AST scanner and linker
    AstScanner.php
    DataFlowVisitor.php
    Linker.php
    AstResult.php
    Discovered*.php
  Console/
    CompileCommand.php      Symfony Console command
  DSL/                      Threat model data classes
    ThreatModel.php
    TechnicalAsset.php
    DataAsset.php
    TrustBoundary.php
    CommunicationLink.php
  Enums/                    All enum types
    Authentication.php
    Authorization.php
    ...
  Yaml/
    ThreagileSerializer.php Threagile YAML serializer
example/
  threat-model.php          Example DSL file
  src/
    UserController.php      Example annotated controller
```

---

## License

MIT
