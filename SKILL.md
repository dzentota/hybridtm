# HybridTM — AI Agent Reference Guide

HybridTM is a PHP threat-modeling platform. Two things live in this
repository:

1. **The `hybridtm/hybridtm` library** (`src/`) — the DSL, code
   attributes, Knowledge Base loader, and Rule Engine described below.
   It generates [Threagile](https://threagile.io)-compatible YAML and
   also runs its own rule-based analysis directly.
2. **HybridTM Studio** — `apps/api/` (a Symfony + API Platform REST API:
   multi-tenancy, RBAC, model workflow, reports) and `apps/studio/` (a
   React canvas editor). Both consume the library; neither duplicates
   its logic. If you're asked to touch the API or Studio, the library
   sections below (Knowledge Base, Rule Engine) are what they're built
   on top of — read those first.

A model is built from up to three sources, layered:

1. **Infrastructure DSL** (`threat-model.php`) — assets, data flows, trust boundaries.
2. **Code attributes** (`#[DataFlow]`, `#[Mitigation]`, etc.) — annotating real source code, scanned statically.
3. **Knowledge Base components** (YAML, `kind: Component`) — a palette entry a DSL `TechnicalAsset` can link to via traits/properties, carrying its own rules. This is what the Rule Engine (as opposed to the Threagile compiler) actually runs against.

Which of these to use depends on the task: annotating an existing PHP app → attributes; describing infrastructure that has no corresponding KB component yet → plain DSL properties/traits; adding a new reusable component type (e.g. "we now support Kafka") → author a KB Component (see the **Knowledge Base** section below) so every future model gets it from the palette instead of hand-rolling traits each time.

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

Pass `--source=` to `analyze` so `component.hasMitigationFor('CWE-…')` uses these discoveries.

---

### `#[AbuserStory(...)]`

**Target:** class, method, or function (repeatable)  
Links the annotated code to an Abuser Story id (`AbuseCase` in the DSL / `abuseCases` in canonical JSON). Place next to `#[Mitigation]` so story coverage can prove required CWEs are mitigated for that story.

| Parameter | Type     | Default      | Description        |
|-----------|----------|--------------|--------------------|
| `id`      | `string` | _(required)_ | AbuseCase / story id |

```php
#[AbuserStory('brute-force-login')]
#[Mitigation(cwe: 'CWE-307', description: 'Account lockout')]
public function authenticate(...): ?string { ... }
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

// Traits and properties (§ Knowledge Base below) — what KB rules
// actually match against. `traits` is a plain list of strings; a rule
// checks them with `component.hasTrait('datastore')` in its `when`.
// `properties` is a PropertyBag: typed key/value pairs a rule reads via
// `component.props.bool('encryption_at_rest')` / `.string(...)` /
// `.int(...)`. An unset property key reads back as the type's zero
// value (false / '' / 0) — rule authors write conditions knowing this,
// so leaving a property unset is never "unknown", it's "off".
$asset->traits = ['datastore', 'sql_engine'];
$asset->properties->set('encryption_at_rest', false);
$asset->properties->set('version', '16.2');

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

**Threat Actor dataflows.** A Threat Actor component (`threat-actor-*` in the
KB, trait `threat_actor`) is not a channel like `Client` — it's the
adversary, so it normally does **not** flow through a `Client`. It targets
the same entry point a legitimate client would, but without that client's
protections (cert pinning, jailbreak detection), so the reachability rule
(`RuleContextGraph::pathsFromThreatActors()`) can tell the two apart:

```php
// Parallel to the legitimate channel — bypasses client-side controls entirely.
$client->communicatesTo('api', Protocol::Https, Authentication::Credentials);
$attacker->communicatesTo('api', Protocol::Https, Authentication::None);
```

The one case where a Threat Actor *should* flow into a `Client` is modeling
a **compromised client device** (malware, theft, session hijack) — the
actor is taking over the channel, not calling over it, so there's no real
network protocol involved:

```php
$attacker->communicatesTo('mobile-client', Protocol::Unknown, Authentication::None);
```

`pathsFromThreatActors()` then continues the walk from `mobile-client`
onward using the attacker's `privilege_level`, so a compromised device
correctly inherits whatever that client could already reach.

---

## Knowledge Base (KB)

The KB is a directory tree of YAML files, one entity per file, validated
against JSON Schemas in `schema/kb/*.json` (canonical examples in
`examples/kb/*.json` — copy one as a starting point rather than writing
a file from scratch). Loaded via `HybridTM\Kb\YamlKbLoader`, which also
resolves `spec.extends` chains (a concrete component inheriting traits/
properties/rules from an abstract parent).

Five kinds, identified by `kind:` in the YAML:

| Kind | Id pattern | Purpose |
|---|---|---|
| `Component` | `web-server-nginx`, `abstract/reverse-proxy` | A palette entry: traits, properties, ports, which rules apply |
| `Threat` | `THREAT-SOME-NAME` | Title, summary, STRIDE, base likelihood/impact, standards mappings (CWE/CAPEC/OWASP/...) |
| `Countermeasure` | `CM-SOME-NAME` | Remediation: cost/effort/effectiveness, per-product implementation hints |
| `Rule` | `category/some-rule` | `when`/`unless`/`then` condition — see **Rule Engine** below |
| `Trait` | `snake_case_name` | Documents a trait string (label/description) — optional; `hasTrait()` works without one, this is for the Studio palette's benefit |

### Authoring a component

```yaml
apiVersion: hybridtm.io/kb/v1
kind: Component
metadata:
  id: db-mysql
  name: MySQL
  version: 1.0.0
  categories: [data, datastore]
  maturity: stable
spec:
  extends: abstract/relational-db   # inherits traits/properties/rules from the parent
  mapping:
    type: datastore                 # REQUIRED on every file, even with extends — the
                                     # schema validates each file standalone, before extends
                                     # resolution ever runs, so the parent's `type` doesn't count
    technologies: [database]
  traits: []                        # extra traits beyond what's inherited, if any
  properties:
    - { id: version, label: 'MySQL version', type: string, group: 'General' }
  rules: []                         # extra rule ids beyond what's inherited — see caveat below
```

**The one rule-scoping mistake to avoid:** a component's `rules:` list is
palette-display metadata only (the Studio "N rules" badge) — the Rule
Engine evaluates *every* component-scope rule in the KB against *every*
technical asset in the model, filtered only by the rule's own `when`
condition. If you give a component a property that only *it* declares
(say `server_tokens_off` on one nginx-like component) and scope the
rule via a trait that *other* components sharing that trait also have
(`hasTrait('http_server')`), every other http_server component gets
evaluated against a property it never declared — and since an unset
property reads as its zero value, a `== false` check spuriously fires
on all of them. Fix: put the property on the shared abstract ancestor
(making it genuinely universal to everything with that trait), or
scope the rule with a trait specific enough that only the intended
components have it (add a new, narrower trait to just those
components — traits have no such false-positive risk, since
`hasTrait()` is a real membership check, not a property read with a
type-zero fallback).

### Authoring a rule

```yaml
apiVersion: hybridtm.io/kb/v1
kind: Rule
metadata:
  id: storage/unencrypted-at-rest
  priority: 100
spec:
  scope: component   # component | flow | boundary | model
  description: 'Datastore holding data without encryption at rest.'
  when:
    all:
      - "component.hasTrait('datastore')"
      - "component.props.bool('encryption_at_rest') == false"
  unless:
    any:
      - "component.hasMitigationFor('CWE-311')"
  then:
    - raise: THREAT-DATA-AT-REST-UNENCRYPTED
      require: [CM-ENCRYPT-AT-REST]
    - suggest_fix:
        set: { encryption_at_rest: true }
        label: 'Enable encryption at rest'
```

Condition expressions are sandboxed (symfony/expression-language) —
the sandbox is structural, not a runtime interceptor: `component`
(component/flow scope) exposes only `HybridTM\Analysis\Subjects\ComponentSubject`'s
public surface (`id`, `name`, `encryption`, `internet`, `redundant`,
`multiTenant`, `customDevelopedParts`, `outOfScope`, `props`,
`hasTrait(...)`, `hasAllTraits(...)`, `storesConfidentialityAtLeast(...)`,
`hasMitigationFor(...)`); `flow` scope additionally exposes `source`/
`target` (each a `ComponentSubject`), `protocol` (`.value`, `.isEncrypted()`),
`vpn`, `ipFiltered`, `readonly`, `crossesTrustBoundary()`,
`carriesDataAtLeast(...)`. Nothing else is reachable — don't invent new
fields without adding them to the relevant `*Subject` class first.

Real derived traits available to any rule via `hasTrait(...)` (computed
by `HybridTM\Analysis\DeriveEngine`, not declared by any component):
`internet_reachable`, `stores_pii`, `handles_strictly_confidential`,
`single_point_of_failure`, `directly_exposed_datastore`, `behind_waf`.

---

## Rule Engine & Analysis

`HybridTM\Analysis\RuleEngine::analyze(ThreatModel $model, KnowledgeBaseInterface $kb, AnalysisOptions $options): AnalysisResult`
is the pure-function entry point — construct once and reuse across
calls (it caches parsed rule expressions internally). Pipeline: expand →
normalize → validate → derive → component/flow/boundary/model rules →
suppress (via `RiskTracking`) → score → dedup/merge. `AnalysisResult`
carries `findings` (list of `Finding`), `validation` (a
`ValidationReport` — `hasErrors()` stops analysis before rules run),
`stats`, and `inputHash` (sha256 of the canonical model + KB version,
for caching/reproducibility).

```bash
php bin/hybridtm analyze --infra=threat-model.php --kb=apps/api/kb --format=table
php bin/hybridtm analyze --infra=threat-model.php --kb=apps/api/kb --format=json
php bin/hybridtm analyze --infra=threat-model.php --kb=apps/api/kb --format=sarif > results.sarif
php bin/hybridtm analyze --infra=threat-model.php --kb=apps/api/kb --fail-on=critical  # exit 1 if any Critical finding
php bin/hybridtm analyze --infra=threat-model.php --source=src/ --kb=apps/api/kb --fail-on-uncovered-stories
```

`--source` scans for `#[Mitigation]` / `#[AbuserStory]` so `hasMitigationFor` and Abuser Story coverage work. `--fail-on-uncovered-stories` exits non-zero when any story is `uncovered` or `partial`. `AnalysisResult::$storyCoverage` lists per-story status.

`--kb` is repeatable; later paths override earlier ones (KB layering:
`kb-core` → `kb-aws` → an org's own overrides). Omit it entirely to
analyze against an empty KB (DSL-only fields still get validated, but
no component-scope rules can match since no component/trait/rule
content is loaded).

Accepting or deferring a finding: `HybridTM\DSL\RiskTracking`, keyed by
a `Finding::$stableId` (not a human-readable label — get the real value
by running analysis once and reading the finding back, the same way
`threat-model.php`'s own risk-tracking entry does it).

```php
$decision = new RiskTracking($finding->stableId);
$decision->status = DecisionStatus::Deferred;   // Accepted | Mitigated | FalsePositive | Deferred
$decision->justification = '...';
$decision->expiresAt = '2026-12-31';             // required for Accepted/Deferred — never a permanent acceptance
$model->addRiskTracking($decision);
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
