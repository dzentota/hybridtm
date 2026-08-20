<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Validation\Rules\AssetOutsideTrustBoundaryRule;
use PHPUnit\Framework\TestCase;

final class AssetOutsideTrustBoundaryRuleTest extends TestCase
{
    private AssetOutsideTrustBoundaryRule $rule;

    protected function setUp(): void
    {
        $this->rule = new AssetOutsideTrustBoundaryRule();
    }

    public function testFlagsAssetOutsideAnyBoundaryWhenBoundariesExist(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $model->addTechnicalAsset(new TechnicalAsset('orphan'));
        $boundary = new TrustBoundary('dmz');
        $boundary->addAssets('web');
        $model->addTrustBoundary($boundary);

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
        self::assertStringContainsString('orphan', $issues[0]->message);
    }

    public function testSkipsEntirelyWhenModelHasNoTrustBoundaries(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
