<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Validation\Rules\AssetInMultipleTrustBoundariesRule;
use PHPUnit\Framework\TestCase;

final class AssetInMultipleTrustBoundariesRuleTest extends TestCase
{
    private AssetInMultipleTrustBoundariesRule $rule;

    protected function setUp(): void
    {
        $this->rule = new AssetInMultipleTrustBoundariesRule();
    }

    public function testFlagsAssetInTwoBoundaries(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $a = new TrustBoundary('a');
        $a->addAssets('web');
        $b = new TrustBoundary('b');
        $b->addAssets('web');
        $model->addTrustBoundary($a)->addTrustBoundary($b);

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
        self::assertStringContainsString('web', $issues[0]->message);
    }

    public function testPassesWhenAssetInOneBoundary(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $a = new TrustBoundary('a');
        $a->addAssets('web');
        $model->addTrustBoundary($a);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
