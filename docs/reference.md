# Reference: DSL, Attributes, and Enumerations

Complete reference for all HybridTM classes, attributes, and enumerations.

---

## Table of Contents

1. [CLI Commands](#cli-commands)
2. [ThreatModel — Root Model Object](#threatmodel)
3. [TechnicalAsset — Technical Components](#technicalasset)
4. [DataAsset — Data Types](#dataasset)
5. [TrustBoundary — Security Zones](#trustboundary)
6. [CommunicationLink — Connections](#communicationlink)
7. [Code Attributes](#code-attributes)
8. [Enumerations](#enumerations)
9. [Quick Cheat Sheet](#quick-cheat-sheet)

---

## CLI Commands

### `compile`

Compiles the DSL file and PHP attributes into Threagile YAML.

```bash
php bin/hybridtm compile [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--infra=PATH` | `threat-model.php` | Path to the infrastructure DSL file |
| `--source=DIR` | `src/` | Directory to scan for PHP attributes |
| `--out=PATH` | `threagile.yaml` | Output Threagile YAML file |

**Examples:**

```bash
# Standard run
php bin/hybridtm compile

# Explicit paths
php bin/hybridtm compile \
    --infra=security/threat-model.php \
    --source=app/src/ \
    --out=build/threagile.yaml

# Inside Docker (for CI without a local PHP installation)
docker run --rm \
    -v "$(pwd):/app" \
    -w /app \
    php:8.2-cli \
    php bin/hybridtm compile --infra=threat-model.php --source=src/
```

**Console output:**

- `✓ Loaded DSL` — DSL file loaded and valid.
- `✓ Scanned N file(s), found M data flow(s)` — AST scan result.
- `WARNING: [DataFlow@Class::method] ...` — attribute not written to YAML (non-fatal).
- `ERROR: ...` — critical failure (unknown asset ID); exits with code 1.

---

## ThreatModel

Root object of the model. Created in the DSL file and returned via `return $model;`.

```php
use HybridTM\DSL\ThreatModel;

$model = new ThreatModel('System Name');
```

### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `title` | `string` | _(constructor)_ | System / product name |
| `description` | `string` | `''` | Short description |
| `author` | `string` | `''` | Author / model owner |
| `date` | `string` | `''` | Date as `YYYY-MM-DD`; empty → current year |
| `businessCriticality` | `BusinessCriticality` | `Important` | Business criticality level |
| `managementSummaryComment` | `string` | `''` | Executive summary comment |

### Methods

| Method | Description |
|--------|-------------|
| `addDataAsset(DataAsset)` | Add a data type; returns `$this` |
| `addTechnicalAsset(TechnicalAsset)` | Add a component; returns `$this` |
| `addTrustBoundary(TrustBoundary)` | Add a trust boundary; returns `$this` |
| `getDataAsset(string $id)` | Find a DataAsset by ID, or `null` |
| `getTechnicalAsset(string $id)` | Find a TechnicalAsset by ID, or `null` |
| `getDataAssets()` | All DataAssets indexed by ID |
| `getTechnicalAssets()` | All TechnicalAssets indexed by ID |
| `getTrustBoundaries()` | All TrustBoundaries indexed by ID |

---

## TechnicalAsset

Represents a technical component: a service, database, external system, or client.

```php
use HybridTM\DSL\TechnicalAsset;

$asset = new TechnicalAsset('asset-id', 'Human-Readable Name');
// If name is omitted, it defaults to the id.
```

### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | _(constructor)_ | Unique ID (lowercase kebab-case) |
| `name` | `string` | `= id` | Display name |
| `description` | `string` | `''` | Component description |
| `type` | `AssetType` | `Process` | Role in the system |
| `usage` | `DataUsage` | `Business` | Purpose of use |
| `usedAsClientByHuman` | `bool` | `false` | Directly used by humans (browser, mobile app) |
| `outOfScope` | `bool` | `false` | Exclude from threat analysis |
| `justificationOutOfScope` | `string` | `''` | Justification for exclusion |
| `size` | `Size` | `Service` | Component scale |
| `technology` | `Technology` | `WebServiceRest` | Technology type |
| `internet` | `bool` | `false` | Accessible from the internet |
| `machine` | `Machine` | `Virtual` | Execution environment type |
| `encryption` | `Encryption` | `None` | Encryption at-rest |
| `owner` | `string` | `''` | Owner (team name or email) |
| `confidentiality` | `Confidentiality` | `Internal` | Confidentiality level |
| `integrity` | `Integrity` | `Operational` | Integrity requirement |
| `availability` | `Availability` | `Operational` | Availability requirement |
| `justificationCiaRating` | `string` | `''` | Justification for CIA rating |
| `multiTenant` | `bool` | `false` | Serves multiple tenants |
| `redundant` | `bool` | `false` | Duplicated for high availability |
| `customDevelopedParts` | `bool` | `false` | Contains custom-written code |
| `dataAssetsProcessed` | `string[]` | `[]` | IDs of DataAssets processed |
| `dataAssetsStored` | `string[]` | `[]` | IDs of DataAssets stored |
| `dataFormatsAccepted` | `string[]` | `[]` | Accepted data formats |
| `tags` | `string[]` | `[]` | Tags for grouping |

### Methods

#### `communicatesTo()`

Creates a `CommunicationLink` from this asset to a target.

```php
$link = $asset->communicatesTo(
    targetId: 'db',                               // target TechnicalAsset ID
    protocol: Protocol::JdbcEncrypted,
    authentication: Authentication::Credentials,
    authorization: Authorization::TechnicalUser,
    description: 'SQL queries to main DB',
);

// Configure the link further as needed:
$link->dataSent     = ['user-data'];
$link->dataReceived = ['query-result'];
$link->vpn          = false;
$link->readonly     = false;
```

**Link ID** is automatically formed as `{sourceId}-to-{targetId}`.

---

## DataAsset

Describes a type of data that flows through or is stored in the system.

```php
use HybridTM\DSL\DataAsset;

$asset = new DataAsset('asset-id', 'Human-Readable Name');
```

### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | _(constructor)_ | Unique ID |
| `name` | `string` | `= id` | Display name |
| `description` | `string` | `''` | Description |
| `usage` | `DataUsage` | `Business` | Purpose of use |
| `origin` | `DataOrigin` | `Unknown` | Data source |
| `owner` | `string` | `''` | Data owner |
| `quantity` | `Quantity` | `Many` | Approximate volume |
| `confidentiality` | `Confidentiality` | `Internal` | Confidentiality level |
| `integrity` | `Integrity` | `Operational` | Integrity requirement |
| `availability` | `Availability` | `Operational` | Availability requirement |
| `justificationCiaRating` | `string` | `''` | CIA rating justification |
| `tags` | `string[]` | `[]` | Tags |

---

## TrustBoundary

Groups technical assets by trust level. Corresponds to the concept of a security zone.

```php
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\TrustBoundaryType;

$boundary = new TrustBoundary(
    'boundary-id',
    'Boundary Name',
    TrustBoundaryType::NetworkCloudProvider,
);
```

### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | _(constructor)_ | Unique ID |
| `name` | `string` | `= id` | Display name |
| `type` | `TrustBoundaryType` | `NetworkOnPrem` | Boundary type |
| `description` | `string` | `''` | Description |
| `technicalAssetsInside` | `string[]` | `[]` | IDs of assets inside |
| `trustBoundariesNested` | `string[]` | `[]` | IDs of nested boundaries |
| `tags` | `string[]` | `[]` | Tags |

### Methods

#### `addAssets(string ...$assetIds)`

Adds assets to the boundary. Duplicates are ignored. Returns `$this`.

```php
$boundary->addAssets('web-app', 'api-service', 'auth-service');
```

---

## CommunicationLink

Describes a connection between two technical assets. Created via `TechnicalAsset::communicatesTo()`.

### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | _(auto)_ | `{sourceId}-to-{targetId}` |
| `targetAssetId` | `string` | _(constructor)_ | Target asset ID |
| `protocol` | `Protocol` | `Https` | Transport protocol |
| `authentication` | `Authentication` | `None` | Authentication mechanism |
| `authorization` | `Authorization` | `None` | Authorisation mechanism |
| `description` | `string` | `''` | Flow description |
| `usage` | `DataUsage` | `Business` | Purpose of use |
| `vpn` | `bool` | `false` | Traffic over VPN |
| `ipFiltered` | `bool` | `false` | IP filtering applied |
| `readonly` | `bool` | `false` | Read-only link |
| `dataSent` | `string[]` | `[]` | IDs of DataAssets sent |
| `dataReceived` | `string[]` | `[]` | IDs of DataAssets received |
| `tags` | `string[]` | `[]` | Tags |

---

## Code Attributes

### `#[AssetId(string $id)]`

**Target:** class  
**Purpose:** links the annotated class to a `TechnicalAsset` in the DSL by ID.

```php
#[AssetId('web-app')]
class UserController { ... }
```

- Only one `#[AssetId]` per class.
- The ID must exactly match `TechnicalAsset::$id` in the DSL.
- Without `#[AssetId]`, `#[DataFlow]` emits a warning and does not generate a link.

---

### `#[DataFlow(...)]`

**Target:** method or function (repeatable)  
**Purpose:** declares a data flow from the source asset (`#[AssetId]`) to a target asset.

```php
#[DataFlow(
    target: 'db',                               // required
    protocol: Protocol::JdbcEncrypted,          // default: Https
    authentication: Authentication::Credentials, // default: None
    authorization: Authorization::TechnicalUser, // default: None
    dataSent: ['user-data'],                    // default: []
    dataReceived: ['query-result'],             // default: []
    vpn: false,                                 // default: false
    ipFiltered: false,                          // default: false
    readonly: false,                            // default: false
)]
public function save(array $data): void {}
```

**Multiple flows on one method** (e.g. the method calls two services):

```php
#[DataFlow(target: 'auth-service', protocol: Protocol::Https, dataSent: ['session-token'])]
#[DataFlow(target: 'audit-log',    protocol: Protocol::Https, dataSent: ['order-data'])]
public function checkout(array $cart): string {}
```

**Deduplication:** if a `communicatesTo()` link already exists in the DSL for the same source → target pair, the compiler enriches it with data from the attribute rather than replacing it.

---

### `#[Mitigation(...)]`

**Target:** class, method, or function (repeatable)  
**Purpose:** documents an implemented security control or an accepted risk.

```php
#[Mitigation(
    cwe: 'CWE-89',                          // required: CWE identifier
    description: 'PDO prepared statements', // required: description
    status: MitigationStatus::Mitigated,    // default: Mitigated
)]
public function findUser(int $id): array {}
```

**Statuses:**

| Constant | Value | When to use |
|----------|-------|-------------|
| `MitigationStatus::Mitigated` | `mitigated` | Control is implemented and verified |
| `MitigationStatus::InProgress` | `in-progress` | Work in progress |
| `MitigationStatus::Accepted` | `accepted` | Risk accepted (justification required) |
| `MitigationStatus::Unchecked` | `unchecked` | Not yet reviewed |

---

### `#[ProcessesData(dataAssets: [...])]`

**Target:** class or method (repeatable)  
**Purpose:** explicitly declares which DataAssets a component processes.

```php
#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['user-pii', 'session-token', 'payment-data'])]
class UserController {}
```

Use this to document data processing even when there are no outbound `#[DataFlow]` calls from the component.

---

## Enumerations

### `AssetType` — Component Role

| Constant | YAML value | When to use |
|----------|-----------|-------------|
| `ExternalEntity` | `external-entity` | Browser, mobile client, partner system, end user |
| `Process` | `process` | Service or application that processes data |
| `Datastore` | `datastore` | Database, cache, file store, message queue |

---

### `Authentication` — Authentication Mechanism

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `None` | `none` | No authentication |
| `Credentials` | `credentials` | Username/password, API key |
| `SessionId` | `session-id` | Cookie / session |
| `Token` | `token` | JWT, OAuth Bearer token |
| `ClientCertificate` | `client-certificate` | Mutual TLS (mTLS) |
| `TwoFactor` | `two-factor` | Two-factor / MFA |
| `ExternalizedViaGateway` | `externalized-via-gateway` | Auth delegated to API Gateway / APIM |

---

### `Authorization` — Authorisation Mechanism

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `None` | `none` | No authorisation |
| `TechnicalUser` | `technical-user` | Service account / technical user |
| `EnduserIdentityPropagation` | `enduser-identity-propagation` | End-user identity propagated (OIDC, JWT claims) |

---

### `Protocol` — Transport Protocol

| Constant | YAML value | Typical use |
|----------|-----------|-------------|
| `Https` | `https` | REST API, web applications |
| `Http` | `http` | Internal unencrypted (not recommended) |
| `Wss` | `wss` | WebSocket over TLS |
| `Ws` | `ws` | WebSocket plain |
| `JdbcEncrypted` | `jdbc-encrypted` | JDBC with TLS (PostgreSQL, MySQL) |
| `Jdbc` | `jdbc` | JDBC without TLS (not recommended) |
| `OdbcEncrypted` | `odbc-encrypted` | ODBC with TLS |
| `Odbc` | `odbc` | ODBC without TLS |
| `SqlAccessProtocolEncrypted` | `sql-access-protocol-encrypted` | MySQL protocol with TLS |
| `SqlAccessProtocol` | `sql-access-protocol` | MySQL protocol without TLS |
| `NosqlAccessProtocolEncrypted` | `nosql-access-protocol-encrypted` | MongoDB, Redis with TLS |
| `NosqlAccessProtocol` | `nosql-access-protocol` | MongoDB, Redis without TLS |
| `BinaryEncrypted` | `binary-encrypted` | gRPC, Thrift, binary + TLS |
| `Binary` | `binary` | Binary protocol without TLS |
| `TextEncrypted` | `text-encrypted` | Text protocol + TLS |
| `Text` | `text` | Text protocol without TLS |
| `Ssh` | `ssh` | SSH |
| `SshTunnel` | `ssh-tunnel` | SSH tunnelling |
| `SmtpEncrypted` | `smtp-encrypted` | SMTP with STARTTLS / TLS |
| `Smtp` | `smtp` | SMTP without TLS |
| `Ldaps` | `ldaps` | LDAP over TLS |
| `Ldap` | `ldap` | LDAP without TLS (not recommended) |
| `Jms` | `jms` | JMS / AMQP (RabbitMQ, ActiveMQ) |
| `Sftp` | `sftp` | Secure FTP |
| `Ftp` | `ftp` | FTP (not recommended) |
| `Mqtt` | `mqtt` | MQTT (IoT) |
| `LocalFileAccess` | `local-file-access` | File system access |
| `ContainerSpawning` | `container-spawning` | Container spawning (K8s API) |
| `InProcessLibraryCall` | `in-process-library-call` | In-process library call |

---

### `Encryption` — Encryption at-Rest

| Constant | YAML value | When to use |
|----------|-----------|-------------|
| `None` | `none` | No encryption |
| `Transparent` | `transparent` | Transparent disk encryption (TDE, AWS EBS) |
| `DataWithSymmetricSharedKey` | `data-with-symmetric-shared-key` | AES with shared key (AWS KMS, GCP CMEK) |
| `DataWithAsymmetricSharedKey` | `data-with-asymmetric-shared-key` | RSA data encryption |
| `DataWithEnduserIndividualKey` | `data-with-enduser-individual-key` | E2E: key held by the end user |

---

### `Confidentiality` — Confidentiality Level

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Public` | `public` | Public data; no harm from disclosure |
| `Internal` | `internal` | Internal company data |
| `Restricted` | `restricted` | Restricted access (not all employees) |
| `Confidential` | `confidential` | Confidential (PII, trade secrets) |
| `StrictlyConfidential` | `strictly-confidential` | Strictly confidential (passwords, keys, PCI data) |

---

### `Integrity` — Integrity Requirement

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Archive` | `archive` | Archive data; changes are non-critical |
| `Operational` | `operational` | Standard operational integrity |
| `Important` | `important` | Integrity loss is noticeable and problematic |
| `Critical` | `critical` | Integrity loss causes outages |
| `MissionCritical` | `mission-critical` | Integrity loss is catastrophic |

---

### `Availability` — Availability Requirement

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Archive` | `archive` | Rare access; downtime acceptable |
| `Operational` | `operational` | Planned downtime acceptable |
| `Important` | `important` | Downtime is noticeable and undesirable |
| `Critical` | `critical` | Downtime causes business losses |
| `MissionCritical` | `mission-critical` | Any downtime is catastrophic |

---

### `Technology` — Technology Type

| Constant | YAML value | Typical component |
|----------|-----------|-------------------|
| `Browser` | `browser` | Web browser |
| `Desktop` | `desktop` | Desktop application |
| `MobileApp` | `mobile-app` | iOS / Android app |
| `WebApplication` | `web-application` | Monolith web app (Symfony, Laravel) |
| `WebServiceRest` | `web-service-rest` | REST API microservice |
| `WebServiceSoap` | `web-service-soap` | SOAP web service |
| `WebServer` | `web-server` | Nginx, Apache |
| `ApplicationServer` | `application-server` | Tomcat, JBoss |
| `Database` | `database` | PostgreSQL, MySQL, MongoDB |
| `IdentityProvider` | `identity-provider` | Keycloak, Okta, Auth0 |
| `LdapServer` | `ldap-server` | Active Directory, OpenLDAP |
| `ReverseProxy` | `reverse-proxy` | Nginx reverse proxy |
| `LoadBalancer` | `load-balancer` | HAProxy, AWS ALB |
| `Waf` | `waf` | Web Application Firewall |
| `MessageQueue` | `message-queue` | RabbitMQ, Kafka, SQS |
| `StreamProcessing` | `stream-processing` | Kafka Streams, Flink |
| `BatchProcessing` | `batch-processing` | Batch jobs, ETL |
| `Function` | `function` | Lambda, Cloud Functions |
| `ContainerPlatform` | `container-platform` | Kubernetes, ECS |
| `Monitoring` | `monitoring` | Prometheus, Grafana, Datadog |
| `BuildPipeline` | `build-pipeline` | Jenkins, GitHub Actions |
| `SourcecodeRepository` | `sourcecode-repository` | GitHub, GitLab |
| `Vault` | `vault` | HashiCorp Vault, AWS Secrets Manager |
| `Erp` | `erp` | SAP, Microsoft Dynamics |
| `SearchIndex` | `search-index` | Elasticsearch, OpenSearch |
| `DataLake` | `data-lake` | S3, BigQuery |
| `Gateway` | `gateway` | API Gateway (Kong, AWS API GW) |
| `Scheduler` | `scheduler` | Cron, AWS EventBridge |
| `Mainframe` | `mainframe` | IBM z/OS |
| `Ai` | `ai` | ML service, LLM endpoint |
| `Cli` | `cli` | Command-line tool |

---

### `Machine` — Execution Environment

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Physical` | `physical` | Physical server / bare metal |
| `Virtual` | `virtual` | Virtual machine (VMware, EC2) |
| `Container` | `container` | Docker container / K8s pod |
| `Serverless` | `serverless` | Lambda, Cloud Functions |

---

### `Size` — Component Scale

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `System` | `system` | Large system (multiple services) |
| `Service` | `service` | Individual service / application |
| `Application` | `application` | Application with multiple modules |
| `Component` | `component` | Small component, library |

---

### `TrustBoundaryType` — Trust Boundary Type

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `NetworkOnPrem` | `network-on-prem` | On-premise network / data centre |
| `NetworkDedicatedHoster` | `network-dedicated-hoster` | Dedicated hosting |
| `NetworkVirtualLan` | `network-virtual-lan` | VLAN |
| `NetworkCloudProvider` | `network-cloud-provider` | VPC (AWS, GCP, Azure) |
| `NetworkCloudSecurityGroup` | `network-cloud-security-group` | Security Group / firewall |
| `NetworkPolicyNamespaceIsolation` | `network-policy-namespace-isolation` | K8s Namespace with NetworkPolicy |
| `ExecutionEnvironment` | `execution-environment` | OS / runtime execution environment |

---

### `DataOrigin` — Data Source

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Unknown` | `unknown` | Source not determined |
| `UserInput` | `ui-input` | User input (form, API request) |
| `FileImport` | `file-import` | Imported from a file |
| `DeviceAccess` | `device-access` | Data from a device (IoT, mobile) |
| `ServiceCall` | `service-call` | Received from another service |
| `TransferredFromPartner` | `transferred-from-partner` | Transferred by a partner / third party |
| `InHouse` | `in-house` | Generated internally by the system |

---

### `DataUsage` — Data Usage Purpose

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Business` | `business` | Business data (primary flow) |
| `DevOps` | `devops` | Infrastructure / DevOps data |

---

### `Quantity` — Approximate Data Volume

| Constant | YAML value | Guideline |
|----------|-----------|-----------|
| `VeryFew` | `very-few` | < 100 records |
| `Few` | `few` | 100 – 10,000 |
| `Many` | `many` | 10,000 – 1,000,000 |
| `VeryMany` | `very-many` | > 1,000,000 |

---

### `BusinessCriticality` — Business Criticality

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Archive` | `archive` | Archive / inactive system |
| `Operational` | `operational` | Supports operations, not critical |
| `Important` | `important` | Important; loss is noticeable |
| `Critical` | `critical` | Critical; loss seriously impacts the business |
| `MissionCritical` | `mission-critical` | Loss = business stoppage |

---

### `MitigationStatus` — Security Control Status

| Constant | YAML value | Description |
|----------|-----------|-------------|
| `Mitigated` | `mitigated` | Implemented and verified |
| `InProgress` | `in-progress` | Work in progress |
| `Accepted` | `accepted` | Risk accepted (justification required) |
| `Unchecked` | `unchecked` | Not yet reviewed |

---

## Quick Cheat Sheet

```php
use HybridTM\Enums\{
    AssetType, Authentication, Authorization, Availability,
    BusinessCriticality, Confidentiality, DataOrigin, DataUsage,
    Encryption, Integrity, Machine, MitigationStatus,
    Protocol, Quantity, Size, Technology, TrustBoundaryType
};

// ── Most common combinations ──────────────────────────────────────────────────

// Browser → REST API (public endpoint)
$browserLink->protocol       = Protocol::Https;
$browserLink->authentication = Authentication::Token;      // JWT / session cookie
$browserLink->authorization  = Authorization::EnduserIdentityPropagation;

// Microservice → Microservice (internal)
$serviceLink->protocol       = Protocol::Https;
$serviceLink->authentication = Authentication::Token;      // service JWT / API key
$serviceLink->authorization  = Authorization::TechnicalUser;

// Service → PostgreSQL (encrypted connection)
$dbLink->protocol       = Protocol::JdbcEncrypted;
$dbLink->authentication = Authentication::Credentials;
$dbLink->authorization  = Authorization::TechnicalUser;

// Service → Redis (NoSQL, TLS)
$redisLink->protocol       = Protocol::NosqlAccessProtocolEncrypted;
$redisLink->authentication = Authentication::Credentials;
$redisLink->authorization  = Authorization::TechnicalUser;

// Service → RabbitMQ (AMQP)
$mqLink->protocol       = Protocol::Jms;
$mqLink->authentication = Authentication::Credentials;
$mqLink->authorization  = Authorization::TechnicalUser;

// gRPC with mutual TLS
$grpcLink->protocol       = Protocol::BinaryEncrypted;
$grpcLink->authentication = Authentication::ClientCertificate;
$grpcLink->authorization  = Authorization::TechnicalUser;

// SSH / SCP
$sshLink->protocol       = Protocol::Ssh;
$sshLink->authentication = Authentication::ClientCertificate;

// External API (Stripe, Twilio, SendGrid, …)
$externalLink->protocol       = Protocol::Https;
$externalLink->authentication = Authentication::Token;      // API key / Bearer
$externalLink->authorization  = Authorization::TechnicalUser;

// LDAP directory lookup
$ldapLink->protocol       = Protocol::Ldaps;
$ldapLink->authentication = Authentication::Credentials;
$ldapLink->authorization  = Authorization::TechnicalUser;

// ── DataAsset sensitivity levels ─────────────────────────────────────────────

// Public content (blog posts, product catalogue)
$public->confidentiality = Confidentiality::Public;
$public->integrity       = Integrity::Operational;
$public->availability    = Availability::Operational;

// Internal business data (orders, inventory)
$internal->confidentiality = Confidentiality::Internal;
$internal->integrity       = Integrity::Important;
$internal->availability    = Availability::Important;

// Personal data / PII (names, emails, addresses)
$pii->confidentiality = Confidentiality::Confidential;
$pii->integrity       = Integrity::Important;
$pii->availability    = Availability::Important;

// Authentication credentials (passwords, tokens)
$credentials->confidentiality = Confidentiality::StrictlyConfidential;
$credentials->integrity       = Integrity::Critical;
$credentials->availability    = Availability::Critical;

// Payment card data (PCI DSS scope)
$pci->confidentiality = Confidentiality::StrictlyConfidential;
$pci->integrity       = Integrity::MissionCritical;
$pci->availability    = Availability::Critical;
```
