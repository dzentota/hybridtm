# Abuser Stories

Моделирование угроз через **Abuser Stories** (Misuser Stories) встраивает безопасность в Agile/Scrum в привычном формате User Story — но с точки зрения злоумышленника.

В HybridTM каждая история — первоклассная часть модели: живёт в DSL / canonical JSON, ссылается на threat actor’ов и активы, и проверяется по evidence из `#[AbuserStory]` + `#[Mitigation]` в исходниках.

## Формат истории

```text
Как <злоумышленник>
я хочу <цель атаки>
чтобы <ущерб>
```

В PHP DSL это обогащённый `AbuseCase` (для Threagile по-прежнему экспортируется `abuse_cases` как id → description):

```php
use HybridTM\DSL\AbuseCase;

$story = new AbuseCase('brute-force-login', 'Подбор паролей на логине');
$story->asA = 'анонимный атакующий';
$story->iWant = 'подобрать учётные данные';
$story->soThat = 'захватить аккаунты';
$story->actorId = 'external-attacker';       // TechnicalAsset с trait threat_actor
$story->assetIds = ['auth-service', 'web-app'];
$story->dataAssetIds = ['user-credentials'];
$story->requiredCwes = ['CWE-307'];
$model->addAbuseCase($story);
```

| Поле | Назначение |
|------|------------|
| `id` / `description` | Стабильный slug + свободный текст (JSON `title` / `text`) |
| `asA` / `iWant` / `soThat` | Agile-нарратив |
| `actorId` | Компонент–threat actor |
| `assetIds` / `dataFlowIds` / `dataAssetIds` | Scope архитектуры |
| `threatIds` | ID угроз KB (`THREAT-*`) |
| `requiredCwes` | CWE, которые должны быть митигированы в коде (или выводятся из linked threats) |
| `status` | `open` \| `in-progress` \| `mitigated` \| `accepted` |

## Связь с кодом

Ставьте `#[AbuserStory('…')]` на тот же класс/метод, что и `#[Mitigation]`, закрывающий историю:

```php
use HybridTM\Attributes\{AbuserStory, AssetId, Mitigation};
use HybridTM\Enums\MitigationStatus;

#[AssetId('auth-service')]
class AuthenticationService
{
    #[AbuserStory('brute-force-login')]
    #[Mitigation(
        cwe: 'CWE-307',
        description: 'Блокировка аккаунта после N неудач',
        status: MitigationStatus::Mitigated,
    )]
    public function authenticate(string $email, string $password): ?string { … }
}
```

## Проверка coverage

```bash
php bin/hybridtm analyze \
    --infra=threat-model.php \
    --source=src/ \
    --kb=apps/api/kb \
    --format=table \
    --fail-on-uncovered-stories
```

- `--source` сканирует `#[Mitigation]` / `#[AbuserStory]`, чтобы работали `hasMitigationFor('CWE-…')` и coverage историй.
- Статус истории: `covered`, `partial`, `uncovered` или `accepted`.
- `--fail-on-uncovered-stories` завершает процесс с ненулевым кодом, если есть `uncovered` или `partial`.
- В JSON есть `storyCoverage[]` (`storyId`, `status`, `requiredCwes`, `coveredCwes`, `missingCwes`, `issues`).

История **covered**, когда для каждого required CWE есть discovery со статусом `Mitigated` на том же контексте, где стоит `#[AbuserStory('этот-id')]`. Статус истории `accepted` закрывает её без code evidence.

## Studio

Во вкладке **Stories** (рядом с Findings):

1. Добавьте Abuser Story и заполните нарратив.
2. Привяжите threat actor, активы, потоки, угрозы KB и required CWEs.
3. Запустите анализ — badges coverage приходят из `storyCoverage` в ответе analyze.
4. Выбор истории подсвечивает связанные компоненты и рёбра на холсте.

Проверка по коду по-прежнему через сканирование PHP (`hybridtm analyze --source=…` в CI). MVP Studio показывает полноту модели и coverage из API, когда он есть.

## Пример для CI

```yaml
- name: Abuser Story coverage
  run: |
    php bin/hybridtm analyze \
      --infra=threat-model.php \
      --source=src/ \
      --kb=vendor/hybridtm/hybridtm/apps/api/kb \
      --fail-on-uncovered-stories
```

См. также: [справочник DSL / атрибутов](/ru/reference), [example/](https://github.com/hybridtm/hybridtm/tree/main/example), [SKILL.md](https://github.com/hybridtm/hybridtm/blob/main/SKILL.md).
