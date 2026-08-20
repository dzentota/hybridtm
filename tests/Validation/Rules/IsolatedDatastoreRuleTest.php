<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Validation\Rules\IsolatedDatastoreRule;
use PHPUnit\Framework\TestCase;

final class IsolatedDatastoreRuleTest extends TestCase
{
    private IsolatedDatastoreRule $rule;

    protected function setUp(): void
    {
        $this->rule = new IsolatedDatastoreRule();
    }

    public function testFlagsDatastoreWithoutIncomingLinks(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testPassesWhenDatastoreHasIncomingLink(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testIgnoresNonDatastoreAssets(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
