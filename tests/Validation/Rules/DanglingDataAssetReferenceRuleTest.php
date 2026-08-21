<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Validation\Rules\DanglingDataAssetReferenceRule;
use PHPUnit\Framework\TestCase;

final class DanglingDataAssetReferenceRuleTest extends TestCase
{
    private DanglingDataAssetReferenceRule $rule;

    protected function setUp(): void
    {
        $this->rule = new DanglingDataAssetReferenceRule();
    }

    public function testFlagsUnknownProcessedDataAsset(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('svc');
        $asset->dataAssetsProcessed = ['ghost'];
        $model->addTechnicalAsset($asset);

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
        self::assertStringContainsString('ghost', $issues[0]->message);
    }

    public function testFlagsUnknownLinkDataAsset(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db');
        $link->dataSent = ['ghost'];
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
    }

    public function testPassesWithKnownDataAssets(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('customer-pii'));
        $asset = new TechnicalAsset('svc');
        $asset->dataAssetsProcessed = ['customer-pii'];
        $asset->dataAssetsStored = ['customer-pii'];
        $model->addTechnicalAsset($asset);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
