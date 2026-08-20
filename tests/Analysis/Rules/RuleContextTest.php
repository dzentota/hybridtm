<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\Rules\RuleContext;
use HybridTM\Analysis\Rules\RuleContextGraph;
use HybridTM\Analysis\Rules\RuleContextModel;
use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Kb\InMemoryKnowledgeBase;
use HybridTM\Kb\Kind;
use PHPUnit\Framework\TestCase;

final class RuleContextTest extends TestCase
{
    /** @param array<string, mixed> $config */
    private function context(?InMemoryKnowledgeBase $kb = null, array $config = []): RuleContext
    {
        $model = new ThreatModel('App');
        return new RuleContext(
            'topology/unguarded-path-from-internet',
            new RuleContextModel($model, new DerivedTraits()),
            new RuleContextGraph($model, \HybridTM\Analysis\ModelIndex::build($model), new DerivedTraits()),
            $kb ?? $this->kb(),
            $config,
        );
    }

    private function kb(): InMemoryKnowledgeBase
    {
        return new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-X' => [
                    'title' => 'Threat X',
                    'summary' => 'summary',
                    'stride' => ['tampering'],
                    'countermeasures' => ['CM-BASE'],
                    'standards' => ['cwe' => [79]],
                    'metadata' => ['id' => 'THREAT-X'],
                ],
            ],
        ], 'test-kb');
    }

    public function testConfigReturnsValue(): void
    {
        $ctx = $this->context(config: ['max_hops' => 4]);
        self::assertSame(4, $ctx->config('max_hops'));
    }

    public function testConfigReturnsDefaultWhenMissing(): void
    {
        $ctx = $this->context();
        self::assertSame('fallback', $ctx->config('nonexistent', 'fallback'));
        self::assertNull($ctx->config('nonexistent'));
    }

    public function testRaiseBuildsFindingFromKbThreat(): void
    {
        $ctx = $this->context();
        $finding = $ctx->raise(
            threat: 'THREAT-X',
            subject: SubjectRef::component('db'),
            likelihood: Likelihood::VeryLikely,
            impact: Impact::VeryHigh,
            evidence: 'evidence text',
            require: ['CM-EXTRA'],
        );

        self::assertNotNull($finding);
        self::assertSame('THREAT-X', $finding->threatId);
        self::assertSame('topology/unguarded-path-from-internet', $finding->ruleId);
        self::assertSame('Threat X', $finding->title);
        self::assertSame(['evidence text'], $finding->evidence);
        self::assertSame(['CM-BASE', 'CM-EXTRA'], $finding->countermeasureIds);
        self::assertSame([79], $finding->standards->cwe);
    }

    public function testRaiseReturnsNullForUnknownThreat(): void
    {
        $ctx = $this->context();
        self::assertNull($ctx->raise('THREAT-NONEXISTENT', SubjectRef::component('x'), Likelihood::Likely, Impact::Low));
    }
}
