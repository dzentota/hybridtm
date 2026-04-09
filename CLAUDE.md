# CLAUDE.md — HybridTM Agent Protocol for Claude Code

This repository uses the **HybridTM** PHP threat-modeling framework. You MUST follow the security annotation protocol when writing or modifying PHP source code.

## Read First

The full agent instructions are in `.github/copilot-instructions.md`. Read that file before making any code changes.

The DSL reference and attribute API are documented in `SKILL.md`.

## TL;DR

1. **Every PHP class** that communicates across a service boundary needs `#[AssetId('...')]` + `#[DataFlow(...)]` + `#[ProcessesData(...)]`.
2. **Every security control** needs `#[Mitigation(cwe: 'CWE-XXX', description: '...')]`.
3. **All IDs** in attributes (`target`, `dataSent`, `dataReceived`) MUST match IDs declared in `threat-model.php`.
4. **New infrastructure** → update `threat-model.php` FIRST, then annotate code.
5. **Always run** `php bin/hybridtm compile` before finishing and fix all warnings.

## Key Files

| File | Purpose |
|------|---------|
| `threat-model.php` | Infrastructure DSL — declares all assets, data, trust zones |
| `src/` | Application code with HybridTM attributes |
| `SKILL.md` | Full DSL and attribute API reference |
| `.github/copilot-instructions.md` | Complete agent annotation protocol with CWE table and examples |
| `bin/hybridtm compile` | CLI compiler — validates and exports the threat model |

## Example

```php
use HybridTM\Attributes\{AssetId, DataFlow, Mitigation, ProcessesData};
use HybridTM\Enums\{Authentication, Authorization, MitigationStatus, Protocol};

#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['customer-pii'])]
class UserController
{
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii'],
        readonly: false,
    )]
    #[Mitigation(cwe: 'CWE-89', description: 'Parameterised queries via Doctrine ORM')]
    public function save(array $data): void { ... }
}
```
