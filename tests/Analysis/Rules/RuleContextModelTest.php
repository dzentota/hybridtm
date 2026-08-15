<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\Rules\RuleContextModel;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use PHPUnit\Framework\TestCase;

final class RuleContextModelTest extends TestCase
{
    public function testDatastoresWithTraitRequiresBothDatastoreAndGivenTrait(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $cache = new TechnicalAsset('cache');
        $cache->traits = ['datastore'];
        $web = new TechnicalAsset('web');
        $web->traits = ['handles_strictly_confidential'];
        $model->addTechnicalAsset($db)->addTechnicalAsset($cache)->addTechnicalAsset($web);

        $ctxModel = new RuleContextModel($model, new DerivedTraits());
        $result = $ctxModel->datastoresWithTrait('handles_strictly_confidential');

        self::assertCount(1, $result);
        self::assertSame('db', $result[0]->id);
    }

    public function testDatastoresWithTraitUnionsDerivedTraits(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $derived = new DerivedTraits();
        $derived->add('db', 'handles_strictly_confidential');

        $ctxModel = new RuleContextModel($model, $derived);
        self::assertCount(1, $ctxModel->datastoresWithTrait('handles_strictly_confidential'));
    }

    public function testAssetsWithTraitsRequiresAll(): void
    {
        $model = new ThreatModel('App');
        $a = new TechnicalAsset('a');
        $a->traits = ['x', 'y'];
        $b = new TechnicalAsset('b');
        $b->traits = ['x'];
        $model->addTechnicalAsset($a)->addTechnicalAsset($b);

        $ctxModel = new RuleContextModel($model, new DerivedTraits());
        $result = $ctxModel->assetsWithTraits('x', 'y');

        self::assertCount(1, $result);
        self::assertSame('a', $result[0]->id);
    }

    public function testUnwrapReturnsUnderlyingModel(): void
    {
        $model = new ThreatModel('App');
        self::assertSame($model, (new RuleContextModel($model, new DerivedTraits()))->unwrap());
    }
}
