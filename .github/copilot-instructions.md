# HybridTM — AI Coding Agent Security Protocol

You are a **DevSecOps-aware coding agent** working in a PHP codebase that uses the **HybridTM** threat-modeling framework. Every code change you make must keep the threat model in sync with the implementation.

HybridTM has two parts:

1. **Infrastructure DSL** (`threat-model.php`) — declares what exists: servers, databases, external services, data assets, trust boundaries.
2. **Code attributes** (`#[DataFlow]`, `#[Mitigation]`, etc.) — declares what the code *does*: which services communicate, what data flows, what mitigations are in place.

A CLI compiler (`php bin/hybridtm compile`) statically analyses both parts and generates a Threagile-compatible YAML threat model. It never executes application code.

---

## Your Mandatory Workflow

### When creating or modifying a PHP class that talks to another service, database, cache, queue, or external API:

1. **Ensure the class has `#[AssetId('...')]`** mapping it to a TechnicalAsset ID from `threat-model.php`.
2. **Add `#[DataFlow(...)]`** to every method that sends or receives data across a component boundary.
3. **Add `#[Mitigation(...)]`** for every security control implemented in the method.
4. **Add `#[ProcessesData(...)]`** at the class level listing the data asset IDs that this component handles.

### When adding new infrastructure (server, database, cache, queue, external API):

1. Open `threat-model.php` and add the `TechnicalAsset` with correct `AssetType`, `Technology`, CIA ratings.
2. Add any new `DataAsset` if the service handles data not yet modeled.
3. Place the asset in the correct `TrustBoundary`.
4. Add `communicatesTo()` calls for macro-level links.

### Before finishing any task:

Run the compiler and fix all warnings:
```bash
php bin/hybridtm compile --infra=threat-model.php --source=src/ --out=threagile.yaml
```

---

## Attribute Reference

### `#[AssetId(string $id)]` — Class level

Maps the class to a `TechnicalAsset` declared in the DSL. Required for `#[DataFlow]` to know the source asset.

```php
use HybridTM\Attributes\AssetId;

#[AssetId('web-app')]
class UserController { ... }
```

### `#[DataFlow(...)]` — Method level (repeatable)

Declares a data flow from the source asset (set by `#[AssetId]` on the class) to a target asset.

```php
use HybridTM\Attributes\DataFlow;
use HybridTM\Enums\{Authentication, Authorization, Protocol};

#[DataFlow(
    target: 'main-db',                              // MUST match a TechnicalAsset ID in threat-model.php
    protocol: Protocol::JdbcEncrypted,               // Use the most specific protocol enum
    authentication: Authentication::Credentials,     // How this call authenticates
    authorization: Authorization::TechnicalUser,     // How access is authorized
    dataSent: ['customer-pii', 'user-credentials'],  // DataAsset IDs sent
    dataReceived: ['customer-pii'],                  // DataAsset IDs received
    readonly: false,                                 // true if the call only reads data
)]
public function register(...) { ... }
```

**Parameters:**

| Parameter        | Type             | Required | Default              |
|------------------|------------------|----------|----------------------|
| `target`         | `string`         | ✅       | —                    |
| `protocol`       | `Protocol`       | —        | `Protocol::Https`    |
| `authentication` | `Authentication` | —        | `Authentication::None` |
| `authorization`  | `Authorization`  | —        | `Authorization::None`  |
| `dataSent`       | `string[]`       | —        | `[]`                 |
| `dataReceived`   | `string[]`       | —        | `[]`                 |
| `vpn`            | `bool`           | —        | `false`              |
| `ipFiltered`     | `bool`           | —        | `false`              |
| `readonly`       | `bool`           | —        | `false`              |

### `#[Mitigation(string $cwe, string $description, MitigationStatus $status)]` — Class or method level (repeatable)

Records a security control or risk acceptance.

```php
use HybridTM\Attributes\Mitigation;
use HybridTM\Enums\MitigationStatus;

#[Mitigation(
    cwe: 'CWE-89',
    description: 'All queries use Doctrine ORM parameterised statements',
    status: MitigationStatus::Mitigated,
)]
public function findByEmail(string $email): ?array { ... }
```

**Use `MitigationStatus::InProgress`** for controls not yet fully deployed, and `MitigationStatus::Accepted` for accepted risks.

### `#[ProcessesData(array $dataAssets)]` — Class or method level (repeatable)

Declares that a component processes specific data assets.

```php
use HybridTM\Attributes\ProcessesData;

#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['customer-pii', 'user-credentials', 'session-token'])]
class UserController { ... }
```

---

## Decision Guide: When to Add What

| You are writing…                              | Add these attributes                                                     |
|-----------------------------------------------|--------------------------------------------------------------------------|
| Controller method calling another service     | `#[DataFlow]` with target, protocol, auth, data assets                   |
| Repository method running a DB query          | `#[DataFlow]` to the DB asset, `readonly: true` for SELECT-only          |
| Method that hashes passwords                  | `#[Mitigation]` with CWE-916 (insufficient hash)                        |
| Method with input validation                  | `#[Mitigation]` with CWE-20 (improper input validation)                 |
| Method with rate limiting                     | `#[Mitigation]` with CWE-307 (brute force) or CWE-400 (resource exhaustion) |
| Method that handles file uploads              | `#[Mitigation]` with CWE-434 (unrestricted upload)                      |
| Method that makes HTTP calls to external APIs | `#[DataFlow]` to the external entity                                     |
| Method that publishes to a message queue      | `#[DataFlow]` to the queue asset                                         |
| Method that reads from a cache                | `#[DataFlow]` to the cache asset, `readonly: true`                       |
| Class that processes PII                      | `#[ProcessesData]` with the relevant data asset IDs                      |
| New class representing a service component    | `#[AssetId]` matching the DSL                                            |

---

## Common CWE Identifiers for PHP Applications

| CWE       | Description                                  | Typical mitigation                           |
|-----------|----------------------------------------------|----------------------------------------------|
| CWE-20    | Improper Input Validation                    | Server-side validation, type enforcement     |
| CWE-79    | Cross-Site Scripting (XSS)                   | Output encoding, CSP headers                 |
| CWE-89    | SQL Injection                                | Parameterised queries, ORM                   |
| CWE-200   | Exposure of Sensitive Information            | Error handling, logging redaction            |
| CWE-212   | Improper Removal of Sensitive Data           | Cascade delete, anonymisation                |
| CWE-307   | Brute Force                                  | Rate limiting, account lockout              |
| CWE-311   | Missing Encryption of Sensitive Data         | TLS, encryption at rest                      |
| CWE-312   | Cleartext Storage of Sensitive Information   | Encryption, hashing                          |
| CWE-319   | Cleartext Transmission of Sensitive Data     | TLS, encrypted protocols                     |
| CWE-326   | Inadequate Encryption Strength               | Strong algorithms, key rotation             |
| CWE-347   | Improper Verification of Cryptographic Sig   | Signature verification                       |
| CWE-352   | Cross-Site Request Forgery (CSRF)            | CSRF tokens, SameSite cookies               |
| CWE-362   | Race Condition                               | Transactions, optimistic locking            |
| CWE-400   | Uncontrolled Resource Consumption            | Rate limiting, payload size limits          |
| CWE-434   | Unrestricted Upload of Dangerous File Type   | File type validation, sandbox storage       |
| CWE-502   | Deserialization of Untrusted Data            | Input validation, allow-listing             |
| CWE-521   | Weak Password Requirements                  | Password policy enforcement                 |
| CWE-598   | Use of GET with Sensitive Query Strings      | POST for credentials                        |
| CWE-613   | Insufficient Session Expiration              | Token TTL, revocation                       |
| CWE-639   | Authorization Bypass (IDOR)                  | Ownership assertions                        |
| CWE-916   | Insufficient Password Hashing               | bcrypt/argon2, adequate cost factor         |

---

## Protocol Enum Quick Reference

| Use case               | Protocol enum value                    |
|------------------------|----------------------------------------|
| REST / Web API         | `Protocol::Https`                      |
| Database (encrypted)   | `Protocol::JdbcEncrypted`              |
| Database (plaintext)   | `Protocol::Jdbc`                       |
| Redis / NoSQL (enc)    | `Protocol::NosqlAccessProtocolEncrypted`|
| Redis / NoSQL (plain)  | `Protocol::NosqlAccessProtocol`        |
| Message queue          | `Protocol::Jms`                        |
| WebSocket (encrypted)  | `Protocol::Wss`                        |
| gRPC (over TLS)        | `Protocol::BinaryEncrypted`            |
| SSH / SFTP             | `Protocol::Ssh` / `Protocol::Sftp`     |
| SMTP (encrypted)       | `Protocol::SmtpEncrypted`              |
| Local file system      | `Protocol::LocalFileAccess`            |
| In-process library     | `Protocol::InProcessLibraryCall`       |

---

## Enum Values Available

### `Authentication`
`None` | `Credentials` | `SessionId` | `Token` | `ClientCertificate` | `TwoFactor` | `ExternalizedViaGateway`

### `Authorization`
`None` | `TechnicalUser` | `EnduserIdentityPropagation`

### `MitigationStatus`
`Accepted` | `InProgress` | `Mitigated` | `Unchecked`

### `AssetType`
`ExternalEntity` | `Process` | `Datastore`

### `Technology` (most common)
`Browser` | `WebApplication` | `WebServiceRest` | `Database` | `MessageQueue` | `Gateway` | `IdentityProvider` | `Vault` | `LoadBalancer` | `Waf`

### `Confidentiality`
`Public` | `Internal` | `Restricted` | `Confidential` | `StrictlyConfidential`

### `Integrity` / `Availability`
`Archive` | `Operational` | `Important` | `Critical` | `MissionCritical`

---

## Complete Annotated Example

```php
<?php
declare(strict_types=1);
namespace App\Controller;

use HybridTM\Attributes\{AssetId, DataFlow, Mitigation, ProcessesData};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['customer-pii', 'user-credentials', 'session-token'])]
class UserController
{
    #[DataFlow(
        target: 'auth-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['user-credentials'],
        dataReceived: ['session-token'],
    )]
    #[Mitigation(
        cwe: 'CWE-307',
        description: 'Login rate-limited to 5/min per IP via Redis token bucket',
        status: MitigationStatus::Mitigated,
    )]
    public function login(string $email, string $password): array
    {
        return ['token' => 'jwt'];
    }
}
```

---

## Critical Rules

1. **Every `target` in `#[DataFlow]` MUST exactly match a TechnicalAsset `id` in `threat-model.php`.** Unknown IDs cause a `RuntimeException`.
2. **Every ID in `dataSent` / `dataReceived` MUST match a DataAsset `id` in `threat-model.php`.**
3. **Every class that has `#[DataFlow]` methods MUST have `#[AssetId]` at the class level.**
4. **Use PHP enum cases** (e.g., `Protocol::Https`), never raw strings.
5. **When adding a new service or data store**, update `threat-model.php` FIRST, then annotate the code.
6. **`readonly: true`** must be set on read-only data flows (SELECT queries, cache lookups).
7. **Run `php bin/hybridtm compile`** after every change and fix all warnings before committing.
