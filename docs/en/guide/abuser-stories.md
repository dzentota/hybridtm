# Abuser Stories

Threat modeling with **Abuser Stories** (also called Misuser Stories) brings security into Agile/Scrum using the familiar User Story shape — but from an attacker's point of view.

HybridTM treats each story as a first-class part of the threat model: it lives in the DSL / canonical JSON, links to threat actors and assets, and is verified against `#[AbuserStory]` + `#[Mitigation]` evidence in source code.

## Story shape

```text
As a <malicious actor>
I want to <attack goal>
so that <impact>
```

In the PHP DSL this is an enriched `AbuseCase` (Threagile still exports `abuse_cases` as id → description for compatibility):

```php
use HybridTM\DSL\AbuseCase;

$story = new AbuseCase('brute-force-login', 'Guess passwords at login');
$story->asA = 'anonymous attacker';
$story->iWant = 'brute-force credentials';
$story->soThat = 'take over accounts';
$story->actorId = 'external-attacker';       // TechnicalAsset with trait threat_actor
$story->assetIds = ['auth-service', 'web-app'];
$story->dataAssetIds = ['user-credentials'];
$story->requiredCwes = ['CWE-307'];
$model->addAbuseCase($story);
```

| Field | Role |
|-------|------|
| `id` / `description` | Stable slug + free-text (JSON `title` / `text`) |
| `asA` / `iWant` / `soThat` | Agile narrative |
| `actorId` | Threat-actor component |
| `assetIds` / `dataFlowIds` / `dataAssetIds` | Architecture scope |
| `threatIds` | KB `THREAT-*` ids |
| `requiredCwes` | CWEs that must be mitigated in code (or derived from linked threats) |
| `status` | `open` \| `in-progress` \| `mitigated` \| `accepted` |

## Link to code

Place `#[AbuserStory('…')]` on the same class/method as the `#[Mitigation]` that closes the story:

```php
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use HybridTM\Enums\MitigationStatus;

#[AssetId('auth-service')]
class AuthenticationService
{
    #[AbuserStory('brute-force-login')]
    #[Mitigation(
        cwe: 'CWE-307',
        description: 'Account lockout after N failures',
        status: MitigationStatus::Mitigated,
    )]
    public function authenticate(string $email, string $password): ?string { … }
}
```

## Verify coverage

```bash
php bin/hybridtm analyze \
    --infra=threat-model.php \
    --source=src/ \
    --kb=apps/api/kb \
    --format=table \
    --fail-on-uncovered-stories
```

- `--source` scans for `#[Mitigation]` / `#[AbuserStory]` so `hasMitigationFor('CWE-…')` and story coverage work.
- Each story becomes `covered`, `partial`, `uncovered`, or `accepted`.
- `--fail-on-uncovered-stories` exits non-zero when any story is `uncovered` or `partial`.
- JSON output includes `storyCoverage[]` (`storyId`, `status`, `requiredCwes`, `coveredCwes`, `missingCwes`, `issues`).

A story is **covered** when every required CWE has a `MitigationStatus::Mitigated` discovery on a context that also carries `#[AbuserStory('that-id')]`. Setting the story status to `accepted` marks it accepted without code evidence.

## Studio

In HybridTM Studio, open the **Stories** tab (next to Findings):

1. Add an Abuser Story and fill the narrative.
2. Link a threat actor, assets, flows, KB threats, and required CWEs.
3. Run analysis — coverage badges come from `storyCoverage` in the analyze response.
4. Selecting a story highlights linked components and edges on the canvas.

Code-level verification still requires scanning PHP (`hybridtm analyze --source=…` in CI). Studio MVP surfaces model completeness and coverage from the API when present.

## CI example

```yaml
- name: Abuser Story coverage
  run: |
    php bin/hybridtm analyze \
      --infra=threat-model.php \
      --source=src/ \
      --kb=vendor/hybridtm/hybridtm/apps/api/kb \
      --fail-on-uncovered-stories
```

See also: [DSL / Attribute Reference](/en/reference), [example/](https://github.com/hybridtm/hybridtm/tree/main/example), [SKILL.md](https://github.com/hybridtm/hybridtm/blob/main/SKILL.md).
