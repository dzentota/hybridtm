<?php
declare(strict_types=1);
namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Validation\Rules\CyclicTrustBoundaryNestingRule;
use PHPUnit\Framework\TestCase;

final class CyclicTrustBoundaryNestingRuleTest extends TestCase
{
    private CyclicTrustBoundaryNestingRule $rule;

    protected function setUp(): void
    {
        $this->rule = new CyclicTrustBoundaryNestingRule();
    }

    public function testFlagsDirectCycle(): void
    {
        $model = new ThreatModel('App');
        $a = new TrustBoundary('a');
        $a->trustBoundariesNested = ['b'];
        $b = new TrustBoundary('b');
        $b->trustBoundariesNested = ['a'];
        $model->addTrustBoundary($a)->addTrustBoundary($b);

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
    }

    public function testFlagsIndirectCycle(): void
    {
        $model = new ThreatModel('App');
        $a = new TrustBoundary('a');
        $a->trustBoundariesNested = ['b'];
        $b = new TrustBoundary('b');
        $b->trustBoundariesNested = ['c'];
        $c = new TrustBoundary('c');
        $c->trustBoundariesNested = ['a'];
        $model->addTrustBoundary($a)->addTrustBoundary($b)->addTrustBoundary($c);

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testPassesOnValidNesting(): void
    {
        $model = new ThreatModel('App');
        $outer = new TrustBoundary('outer');
        $outer->trustBoundariesNested = ['inner'];
        $inner = new TrustBoundary('inner');
        $model->addTrustBoundary($outer)->addTrustBoundary($inner);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testDoesNotDuplicateReportForSameCycle(): void
    {
        $model = new ThreatModel('App');
        $a = new TrustBoundary('a');
        $a->trustBoundariesNested = ['b'];
        $b = new TrustBoundary('b');
        $b->trustBoundariesNested = ['a'];
        $model->addTrustBoundary($a)->addTrustBoundary($b);

        // Iterating from both 'a' and 'b' as DFS roots must not double-report.
        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }
}
