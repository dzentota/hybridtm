# HybridTM — AI Agent Reference Guide

HybridTM is a PHP threat-modeling compiler that generates [Threagile](https://threagile.io)-compatible YAML from two sources:

1. **Infrastructure DSL** — a PHP file declaring assets, data flows, and trust boundaries.
2. **Code attributes** — PHP 8 attributes (`#[DataFlow]`, `#[Mitigation]`, etc.) annotating the real source code.

---

## Two-Part Model

### Part 1 — Infrastructure DSL (`threat-model.php`)

Describes _what exists_ in the system: servers, databases, external actors, data types, trust zones.  
Must end with `return $model;` returning a `HybridTM\DSL\ThreatModel` instance.

### Part 2 — Code Attributes (`src/`)

Annotates _what the code does_: which services communicate, what data flows, which mitigations are in place.  
Scanned statically by the AST compiler — the code never executes.

---

## Attributes

### `#[AssetId(string $id)]`

**Target:** class  
Maps the annotated class to a `TechnicalAsset` declared in the DSL.  
Must be set for `#[DataFlow]` to know the _source_ asset.

```php
#[AssetId('web-app')]
class UserController { ... }
```

---

### `#[DataFlow(...)]`

**Target:** method or function (repeatable)  
Declares a communication link from the source asset (set by `#[AssetId]`) to a target asset.

| Parameter        | Type             | Default              | Description                        |
|------------------|------------------|----------------------|------------------------------------|
| `target`         | `string`         | _(required)_         | ID of the target TechnicalAsset    |
| `protocol`       | `Protocol`       | `Protocol::Https`    | Communication protocol             |
| `authentication` | `Authentication` | `Authentication::None` | Auth mechanism                   |
| `authorization`  | `Authorization`  | `Authorization::None`  | Authz mechanism                  |
| `dataSent`       | `string[]`       | `[]`                 | DataAsset IDs sent                 |
| `dataReceived`   | `string[]`       | `[]`                 | DataAsset IDs received             |
| `vpn`            | `bool`           | `false`              | Is traffic over a VPN?             |
| `ipFiltered`     | `bool`           | `false`              | Is IP filtering applied?           |
| `readonly`       | `bool`           | `false`              | Is the link read-only?             |

```php
#[DataFlow(
    target: 'auth-service',
    protocol: Protocol::Https,
    authentication: Authentication::Token,
    authorization: Authorization::TechnicalUser,
    dataSent: ['user-credentials'],
    dataReceived: ['session-token'],
)]
public function login(array $credentials): array { ... }
```

---

### `#[Mitigation(...)]`

**Target:** class, method, or function (repeatable)  
Records a security control or accepted risk.

| Parameter     | Type               | Default                      | Description           |
|---------------|--------------------|------------------------------|-----------------------|
| `cwe`         | `string`           | _(required)_                 | CWE identifier        |
| `description` | `string`           | _(required)_                 | Mitigation description|
| `status`      | `MitigationStatus` | `MitigationStatus::Mitigated`| Current status        |

```php
#[Mitigation(
    cwe: 'CWE-307',
    description: 'Rate-limit login attempts',
    status: MitigationStatus::Mitigated,
)]
public function login(...) { ... }
```

---

### `#[ProcessesData(array $dataAssets)]`

**Target:** class or method (repeatable)  
Declares that a component processes certain data assets (adds them to `data_assets_processed`).

```php
#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['user-credentials', 'user-profile'])]
class UserController { ... }
```

---

## DSL Classes

### `ThreatModel`

```php
$model = new ThreatModel('My Service');
$model->description = '...';
$model->author = 'Security Team';
$model->date = '2024-01-15';          // YYYY-MM-DD
$model->businessCriticality = BusinessCriticality::Critical;
$model->managementSummaryComment = '...';

$model->addDataAsset($asset);
$model->addTechnicalAsset($asset);
$model->addTrustBoundary($boundary);

// Getters
$model->getDataAssets();        // DataAsset[] keyed by id
$model->getTechnicalAssets();   // TechnicalAsset[] keyed by id
$model->getTrustBoundaries();   // TrustBoundary[] keyed by id
$model->getDataAsset('id');     // ?DataAsset
$model->getTechnicalAsset('id'); // ?TechnicalAsset
```

---

### `DataAsset`

```php
$asset = new DataAsset('asset-id', 'Human Name');
$asset->description = '...';
$asset->usage          = DataUsage::Business;       // or DevOps
$asset->origin         = DataOrigin::UserInput;
$asset->owner          = 'Team Name';
$asset->quantity       = Quantity::Many;
$asset->confidentiality = Confidentiality::Confidential;
$asset->integrity       = Integrity::Important;
$asset->availability    = Availability::Important;
$asset->justificationCiaRating = '...';
$asset->tags           = ['pii', 'gdpr'];
```

---

### `TechnicalAsset`

```php
$asset = new TechnicalAsset('asset-id', 'Human Name');
$asset->description    = '...';
$asset->type           = AssetType::Process;         // ExternalEntity | Process | Datastore
$asset->usage          = DataUsage::Business;
$asset->usedAsClientByHuman = false;
$asset->outOfScope     = false;
$asset->size           = Size::Service;
$asset->technology     = Technology::WebServiceRest;
$asset->internet       = false;
$asset->machine        = Machine::Container;
$asset->encryption     = Encryption::None;
$asset->owner          = 'Team';
$asset->confidentiality = Confidentiality::Internal;
$asset->integrity       = Integrity::Operational;
$asset->availability    = Availability::Operational;
$asset->multiTenant    = false;
$asset->redundant      = false;
$asset->customDevelopedParts = true;
$asset->dataAssetsProcessed = ['asset-id'];
$asset->dataAssetsStored    = ['asset-id'];
$asset->tags               = [];

// Add a communication link fluently:
$link = $asset->communicatesTo('target-id', Protocol::Https, Authentication::Token, Authorization::TechnicalUser, 'description');
$link->dataSent = ['data-id'];
$link->dataReceived = ['data-id'];
```

---

### `TrustBoundary`

```php
$boundary = new TrustBoundary('boundary-id', 'Human Name', TrustBoundaryType::NetworkCloudProvider);
$boundary->description = '...';
$boundary->addAssets('asset-id-1', 'asset-id-2');
$boundary->tags = [];
```

---

### `CommunicationLink`

Returned by `TechnicalAsset::communicatesTo()`. Can also be created manually:

```php
$link = new CommunicationLink('link-id', 'target-asset-id', Protocol::Https);
$link->description    = '...';
$link->authentication = Authentication::Token;
$link->authorization  = Authorization::TechnicalUser;
$link->dataSent       = ['data-id'];
$link->dataReceived   = ['data-id'];
$link->vpn            = false;
$link->ipFiltered     = false;
$link->readonly       = false;
$link->usage          = DataUsage::Business;
$link->tags           = [];
```

---

## Enum Reference

### `AssetType`
`ExternalEntity` | `Process` | `Datastore`

### `Authentication`
`None` | `Credentials` | `SessionId` | `Token` | `ClientCertificate` | `TwoFactor` | `ExternalizedViaGateway`

### `Authorization`
`None` | `TechnicalUser` | `EnduserIdentityPropagation`

### `Availability` / `Integrity`
`Archive` | `Operational` | `Important` | `Critical` | `MissionCritical`

### `BusinessCriticality`
`Archive` | `Operational` | `Important` | `Critical` | `MissionCritical`

### `Confidentiality`
`Public` | `Internal` | `Restricted` | `Confidential` | `StrictlyConfidential`

### `DataOrigin`
`Unknown` | `FileImport` | `UserInput` | `DeviceAccess` | `ServiceCall` | `TransferredFromPartner` | `InHouse`

### `DataUsage`
`Business` | `DevOps`

### `Encryption`
`None` | `Transparent` | `DataWithSymmetricSharedKey` | `DataWithAsymmetricSharedKey` | `DataWithEnduserIndividualKey`

### `Machine`
`Physical` | `Virtual` | `Container` | `Serverless`

### `MitigationStatus`
`Accepted` | `InProgress` | `Mitigated` | `Unchecked`

### `Protocol`
`Unknown` | `Http` | `Https` | `Ws` | `Wss` | `ReverseProxyWebProtocol` | `ReverseProxyWebProtocolEncrypted` | `Mqtt` | `Jdbc` | `JdbcEncrypted` | `Odbc` | `OdbcEncrypted` | `SqlAccessProtocol` | `SqlAccessProtocolEncrypted` | `NosqlAccessProtocol` | `NosqlAccessProtocolEncrypted` | `Binary` | `BinaryEncrypted` | `Text` | `TextEncrypted` | `Ssh` | `SshTunnel` | `Smtp` | `SmtpEncrypted` | `Pop3` | `Pop3Encrypted` | `Imap` | `ImapEncrypted` | `Ftp` | `Ftps` | `Sftp` | `Scp` | `Ldap` | `Ldaps` | `Jms` | `Nfs` | `Smb` | `SmbEncrypted` | `LocalFileAccess` | `Nrpe` | `Xmpp` | `Iiop` | `IiopEncrypted` | `Jrmp` | `JrmpEncrypted` | `InProcessLibraryCall` | `ContainerSpawning`

### `Quantity`
`VeryFew` | `Few` | `Many` | `VeryMany`

### `Size`
`System` | `Service` | `Application` | `Component`

### `Technology`
`Unknown` | `ClientSystem` | `Browser` | `Desktop` | `MobileApp` | `DevopsClient` | `WebServer` | `WebApplication` | `ApplicationServer` | `WebServiceRest` | `WebServiceSoap` | `Database` | `FileServer` | `LocalFileSystem` | `Erp` | `Cms` | `SearchIndex` | `SearchEngine` | `ServiceRegistry` | `ReverseProxy` | `LoadBalancer` | `Waf` | `Ids` | `Ips` | `BuildPipeline` | `SourcecodeRepository` | `ArtifactRegistry` | `CodeInspectionPlatform` | `Monitoring` | `LdapServer` | `IdentityProvider` | `IdentityStoreLdap` | `IdentityStoreDatabase` | `ContainerPlatform` | `BatchProcessing` | `EventListener` | `MessageQueue` | `StreamProcessing` | `ServiceMesh` | `DataLake` | `ReportEngine` | `Ai` | `MailServer` | `Vault` | `Hsm` | `Scheduler` | `Mainframe` | `BlockStorage` | `Gateway` | `IoTDevice` | `Function` | `Tool` | `Cli` | `Library`

### `TrustBoundaryType`
`NetworkOnPrem` | `NetworkDedicatedHoster` | `NetworkVirtualLan` | `NetworkCloudProvider` | `NetworkCloudSecurityGroup` | `NetworkPolicyNamespaceIsolation` | `ExecutionEnvironment`

---

## Compile Command

```bash
php bin/hybridtm compile [options]
```

| Option       | Default            | Description                                      |
|--------------|--------------------|--------------------------------------------------|
| `--infra`    | `threat-model.php` | Path to the infrastructure DSL file              |
| `--source`   | `src/`             | Directory to scan for `#[DataFlow]` attributes   |
| `--out`      | `threagile.yaml`   | Output path for the generated Threagile YAML     |

**Example:**
```bash
php bin/hybridtm compile \
    --infra=example/threat-model.php \
    --source=example/src \
    --out=build/threagile.yaml
```

---

## Complete Worked Example

### DSL File (`threat-model.php`)

```php
<?php
declare(strict_types=1);
require_once __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\{DataAsset, TechnicalAsset, ThreatModel, TrustBoundary};
use HybridTM\Enums\{AssetType, Authentication, Authorization, Availability,
    BusinessCriticality, Confidentiality, DataOrigin, Encryption,
    Integrity, Machine, Protocol, Quantity, Size, Technology, TrustBoundaryType};

$model = new ThreatModel('Payment Service');
$model->businessCriticality = BusinessCriticality::Critical;

$cardData = new DataAsset('card-data', 'Card Data');
$cardData->confidentiality = Confidentiality::StrictlyConfidential;
$cardData->integrity = Integrity::Critical;
$cardData->availability = Availability::Critical;
$cardData->origin = DataOrigin::UserInput;
$model->addDataAsset($cardData);

$api = new TechnicalAsset('payment-api', 'Payment API');
$api->type = AssetType::Process;
$api->technology = Technology::WebServiceRest;
$api->machine = Machine::Container;
$api->customDevelopedParts = true;
$api->encryption = Encryption::None;
$model->addTechnicalAsset($api);

$db = new TechnicalAsset('payment-db', 'Payment DB');
$db->type = AssetType::Datastore;
$db->technology = Technology::Database;
$db->encryption = Encryption::DataWithSymmetricSharedKey;
$db->dataAssetsStored = ['card-data'];
$model->addTechnicalAsset($db);

$link = $api->communicatesTo('payment-db', Protocol::JdbcEncrypted, Authentication::Credentials, Authorization::TechnicalUser);
$link->dataSent = ['card-data'];

$vpc = new TrustBoundary('vpc', 'VPC', TrustBoundaryType::NetworkCloudProvider);
$vpc->addAssets('payment-api', 'payment-db');
$model->addTrustBoundary($vpc);

return $model;
```

### Code Annotation (`src/PaymentController.php`)

```php
<?php
namespace App;

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation, ProcessesData};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

#[AssetId('payment-api')]
#[ProcessesData(dataAssets: ['card-data'])]
class PaymentController
{
    #[DataFlow(
        target: 'payment-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['card-data'],
        dataReceived: ['card-data'],
    )]
    #[Mitigation('CWE-312', 'Card data encrypted at rest using AES-256')]
    #[Mitigation('CWE-319', 'All DB connections use JDBC encrypted protocol')]
    public function processPayment(array $payload): string
    {
        return 'ok';
    }
}
```

---

## Common Mistakes to Avoid

1. **Missing `#[AssetId]`** — Without it, the compiler cannot link `#[DataFlow]` annotations to a source asset. A warning is emitted and the flow is attached to the target only.

2. **Unknown asset IDs in `#[DataFlow]`** — The `target` value must exactly match an ID declared in the DSL. A `RuntimeException` is thrown.

3. **Unknown DataAsset IDs** — All IDs in `dataSent`/`dataReceived` must be declared via `addDataAsset()`. A `RuntimeException` is thrown.

4. **DSL file does not return the model** — The DSL file must end with `return $model;`. Otherwise the compiler fails with a type error.

5. **Mismatched enum values** — Use PHP enum cases (e.g., `Protocol::Https`), not string values, in code attributes.

6. **Scanning the DSL directory** — Pass the application source directory to `--source`, not the directory containing `threat-model.php`. The DSL file itself should not be scanned.

7. **Duplicate communication links** — Calling `communicatesTo()` twice with the same target creates two separate links (keyed `id-to-target`). Use the returned `CommunicationLink` reference to add data assets to an existing link.
