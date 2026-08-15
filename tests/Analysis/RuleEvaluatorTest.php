<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\RuleEvaluator;
use HybridTM\Analysis\RuleExpressionProvider;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Kb\InMemoryKnowledgeBase;
use HybridTM\Kb\Kind;
use PHPUnit\Framework\TestCase;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

final class RuleEvaluatorTest extends TestCase
{
    protected function setUp(): void
    {
        if (!class_exists(ExpressionLanguage::class)) {
            self::markTestSkipped('symfony/expression-language is not installed.');
        }
    }

    /** @param array<string, mixed> $threatOverrides */
    private function kb(array $threatOverrides = []): InMemoryKnowledgeBase
    {
        return new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-DATA-AT-REST-UNENCRYPTED' => array_merge([
                    'title' => 'Unencrypted data at rest',
                    'summary' => 'Confidential data is stored unencrypted.',
                    'stride' => ['information-disclosure'],
                    'base' => ['likelihood' => 'likely', 'impact' => 'medium'],
                    'countermeasures' => ['CM-ENCRYPT-AT-REST'],
                    'standards' => ['cwe' => [311]],
                    'metadata' => ['id' => 'THREAT-DATA-AT-REST-UNENCRYPTED'],
                ], $threatOverrides),
            ],
        ], 'test-kb');
    }

    private function evaluator(?InMemoryKnowledgeBase $kb = null): RuleEvaluator
    {
        return new RuleEvaluator(new RuleExpressionProvider(), $kb ?? $this->kb());
    }

    public function testMatchedWhenAllConditionsPass(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['component.hasTrait(\'datastore\')']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $component = new class { public function hasTrait(string $t): bool { return true; } };

        $result = $this->evaluator()->evaluate('storage/unencrypted', $spec, SubjectRef::component('db'), ['component' => $component]);

        self::assertTrue($result['trace']->matched);
        self::assertCount(1, $result['findings']);
        self::assertSame('THREAT-DATA-AT-REST-UNENCRYPTED', $result['findings'][0]->threatId);
        self::assertSame('storage/unencrypted', $result['findings'][0]->ruleId);
        self::assertSame('component:db', (string) $result['findings'][0]->subject);
    }

    public function testNotMatchedWhenAllConditionFails(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['component.hasTrait(\'datastore\')']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $component = new class { public function hasTrait(string $t): bool { return false; } };

        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('db'), ['component' => $component]);

        self::assertFalse($result['trace']->matched);
        self::assertSame([], $result['findings']);
    }

    public function testAnyConditionMatchesIfOnePasses(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['any' => ['component.a', 'component.b']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $component = new class { public bool $a = false; public bool $b = true; };

        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => $component]);
        self::assertTrue($result['trace']->matched);
    }

    public function testUnlessSuppressesAMatchingWhen(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['component.a']],
            'unless' => ['any' => ['component.mitigated']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $component = new class { public bool $a = true; public bool $mitigated = true; };

        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => $component]);

        self::assertFalse($result['trace']->matched);
        self::assertSame([], $result['findings']);
        self::assertCount(1, $result['trace']->suppressedBy());
    }

    public function testUnlessNotTriggeredLeavesFindingIntact(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['component.a']],
            'unless' => ['any' => ['component.mitigated']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $component = new class { public bool $a = true; public bool $mitigated = false; };

        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => $component]);
        self::assertTrue($result['trace']->matched);
        self::assertCount(1, $result['findings']);
    }

    public function testActionLikelihoodAndImpactOverrideThreatBase(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['true']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED', 'likelihood' => 'frequent', 'impact' => 'very-high']],
        ];
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => new class {}]);

        self::assertSame(\HybridTM\Enums\Likelihood::Frequent, $result['findings'][0]->likelihood);
        self::assertSame(\HybridTM\Enums\Impact::VeryHigh, $result['findings'][0]->impact);
    }

    public function testMissingActionLikelihoodFallsBackToThreatBase(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['true']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => new class {}]);

        self::assertSame(\HybridTM\Enums\Likelihood::Likely, $result['findings'][0]->likelihood);
        self::assertSame(\HybridTM\Enums\Impact::Medium, $result['findings'][0]->impact);
    }

    public function testEvidenceIsRenderedFromTemplate(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['true']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED', 'evidence' => '{{ component.name }} is affected']],
        ];
        $component = new class { public string $name = 'PostgreSQL'; };
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => $component]);

        self::assertSame(['PostgreSQL is affected'], $result['findings'][0]->evidence);
    }

    public function testRequireIsMergedWithThreatCountermeasures(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['true']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED', 'require' => ['CM-KEY-MANAGEMENT-KMS']]],
        ];
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => new class {}]);

        self::assertSame(['CM-ENCRYPT-AT-REST', 'CM-KEY-MANAGEMENT-KMS'], $result['findings'][0]->countermeasureIds);
    }

    public function testStandardsMappingIsPopulatedFromThreat(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['true']],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => new class {}]);

        self::assertSame([311], $result['findings'][0]->standards->cwe);
    }

    public function testUnknownThreatIdProducesNoFinding(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ['true']],
            'then' => [['raise' => 'THREAT-NONEXISTENT']],
        ];
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => new class {}]);

        self::assertTrue($result['trace']->matched, 'the rule itself matched');
        self::assertSame([], $result['findings'], 'but nothing to raise since the threat is unknown');
    }

    public function testBrokenExpressionFailsClosedWithoutThrowing(): void
    {
        $spec = [
            'scope' => 'component',
            'when' => ['all' => ["component.thisMethodDoesNotExist()"]],
            'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
        ];
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::component('x'), ['component' => new class {}]);

        self::assertFalse($result['trace']->matched);
        self::assertSame([], $result['findings']);
        self::assertNotEmpty($result['trace']->failed()[0]->detail);
    }

    public function testSuggestFixActionProducesNoFinding(): void
    {
        $spec = [
            'scope' => 'flow',
            'when' => ['all' => ['true']],
            'then' => [['suggest_fix' => ['set' => ['flow.protocol' => 'https'], 'label' => 'Use HTTPS']]],
        ];
        $result = $this->evaluator()->evaluate('r', $spec, SubjectRef::flow('a', 'b'), ['flow' => new class {}]);

        self::assertTrue($result['trace']->matched);
        self::assertSame([], $result['findings']);
    }
}
