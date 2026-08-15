<?php
declare(strict_types=1);
namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Validation\Rules\DuplicateIdRule;
use PHPUnit\Framework\TestCase;

final class DuplicateIdRuleTest extends TestCase
{
    private DuplicateIdRule $rule;

    protected function setUp(): void
    {
        $this->rule = new DuplicateIdRule();
    }

    public function testFlagsIdSharedAcrossKinds(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('db'));
        $model->addTrustBoundary(new TrustBoundary('db'));

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
        self::assertStringContainsString('db', $issues[0]->message);
    }

    public function testPassesWithDistinctIds(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('db'));
        $model->addTrustBoundary(new TrustBoundary('dmz'));

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
