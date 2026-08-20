<?php

declare(strict_types=1);

namespace HybridTM\Tests\Kb;

use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Enums\Severity;
use HybridTM\Kb\Kind;
use HybridTM\Kb\YamlKbLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Golden-file infrastructure for KB rules (T-11.1): every declarative
 * rule in apps/api/kb must have a fixture pair here — a `positive` model
 * that triggers it and a `negative` model that doesn't — checked by both
 * directions:
 *
 *  - testEveryRuleHasAFixture(): fails if a rule was added to the KB
 *    without a matching tests/Fixtures/Rules/<name>.json — the whole
 *    point of "adding a rule without fixtures breaks CI".
 *  - testFixtureTriggersExpectedThreat() / testNegativeFixtureDoesNotTrigger():
 *    run every fixture pair through the real RuleEngine + the real KB and
 *    assert the expected threat does/doesn't appear.
 *
 * Cross-references apps/api/kb directly rather than a separate example
 * KB: it's the only substantive rule content in this repo (T-8), and
 * this repo hasn't been split into separate composer packages yet
 * (T-0.1 is deferred) — the moment it is, this path is the one line
 * that needs updating.
 */
final class RuleGoldenFileTest extends TestCase
{
    private const KB_PATH = __DIR__ . '/../../apps/api/kb';
    private const FIXTURES_PATH = __DIR__ . '/../Fixtures/Rules';

    public function testEveryDeclarativeRuleHasAFixture(): void
    {
        $kb = (new YamlKbLoader())->load([self::KB_PATH]);
        $fixtureRuleIds = array_column($this->loadAllFixtures(), 'ruleId');

        $missing = [];
        foreach ($kb->ids(Kind::Rule) as $ruleId) {
            $spec = $kb->get(Kind::Rule, $ruleId);
            if (isset($spec['impl'])) {
                continue; // PHP-implemented rules are covered by their own unit tests, not fixtures
            }
            if (!\in_array($ruleId, $fixtureRuleIds, true)) {
                $missing[] = $ruleId;
            }
        }

        self::assertSame(
            [],
            $missing,
            'Every declarative rule needs a tests/Fixtures/Rules/*.json fixture. Missing: ' . implode(', ', $missing),
        );
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function fixtureProvider(): iterable
    {
        foreach ((glob(self::FIXTURES_PATH . '/*.json') ?: []) as $path) {
            yield basename($path) => [json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR)];
        }
    }

    /** @param array<string, mixed> $fixture */
    #[DataProvider('fixtureProvider')]
    public function testPositiveFixtureTriggersExpectedThreat(array $fixture): void
    {
        $threatIds = $this->analyze($fixture['positive']);

        self::assertContains(
            $fixture['expectedThreatId'],
            $threatIds,
            "Rule \"{$fixture['ruleId']}\"'s positive fixture did not produce {$fixture['expectedThreatId']}. Got: " . implode(', ', $threatIds),
        );
    }

    /** @param array<string, mixed> $fixture */
    #[DataProvider('fixtureProvider')]
    public function testNegativeFixtureDoesNotTrigger(array $fixture): void
    {
        $threatIds = $this->analyze($fixture['negative']);

        self::assertNotContains(
            $fixture['expectedThreatId'],
            $threatIds,
            "Rule \"{$fixture['ruleId']}\"'s negative fixture unexpectedly produced {$fixture['expectedThreatId']}.",
        );
    }

    /** @return list<array<string, mixed>> */
    private function loadAllFixtures(): array
    {
        $fixtures = [];
        foreach ((glob(self::FIXTURES_PATH . '/*.json') ?: []) as $path) {
            $fixtures[] = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        }
        return $fixtures;
    }

    /**
     * @param array<string, mixed> $canonicalModel
     * @return list<string>
     */
    private function analyze(array $canonicalModel): array
    {
        static $kb = null;
        $kb ??= (new YamlKbLoader())->load([self::KB_PATH]);

        $model = (new ModelJsonCodec())->decode($canonicalModel);
        $result = (new RuleEngine())->analyze($model, $kb, new AnalysisOptions(minSeverity: Severity::Low));

        return array_map(static fn ($f): string => $f->threatId, $result->findings);
    }
}
