<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Validation\Rules\UnusedDataAssetRule;
use PHPUnit\Framework\TestCase;

final class UnusedDataAssetRuleTest extends TestCase
{
    private UnusedDataAssetRule $rule;

    protected function setUp(): void
    {
        $this->rule = new UnusedDataAssetRule();
    }

    public function testFlagsUnusedDataAsset(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('orphan-data'));

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
        self::assertStringContainsString('orphan-data', $issues[0]->message);
    }

    public function testPassesWhenProcessed(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('customer-pii'));
        $asset = new TechnicalAsset('svc');
        $asset->dataAssetsProcessed = ['customer-pii'];
        $model->addTechnicalAsset($asset);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testPassesWhenOnlyUsedOnALink(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('payload'));
        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db');
        $link->dataSent = ['payload'];
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
