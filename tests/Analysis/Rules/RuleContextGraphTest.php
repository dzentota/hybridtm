<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\Rules\RuleContextGraph;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use PHPUnit\Framework\TestCase;

final class RuleContextGraphTest extends TestCase
{
    private function graph(ThreatModel $model): RuleContextGraph
    {
        return new RuleContextGraph($model, ModelIndex::build($model), new DerivedTraits());
    }

    public function testFindsDirectPathFromInternetFacingAsset(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web);
        $db = new TechnicalAsset('db');
        $model->addTechnicalAsset($db);

        $paths = $this->graph($model)->pathsFromInternet($db, maxHops: 4);

        self::assertCount(1, $paths);
        self::assertSame(['web', 'db'], $paths[0]->assetIds);
    }

    public function testFindsMultiHopPath(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('app');
        $app = new TechnicalAsset('app');
        $app->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($app)->addTechnicalAsset(new TechnicalAsset('db'));

        $db = $model->getTechnicalAsset('db');
        self::assertNotNull($db, 'db asset must exist in the model');
        $paths = $this->graph($model)->pathsFromInternet($db, maxHops: 4);

        self::assertCount(1, $paths);
        self::assertSame(['web', 'app', 'db'], $paths[0]->assetIds);
    }

    public function testRespectsMaxHops(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('app');
        $app = new TechnicalAsset('app');
        $app->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($app)->addTechnicalAsset(new TechnicalAsset('db'));

        $db = $model->getTechnicalAsset('db');
        self::assertNotNull($db, 'db asset must exist in the model');
        $paths = $this->graph($model)->pathsFromInternet($db, maxHops: 1);
        self::assertSame([], $paths, '2-hop path exceeds the 1-hop budget');
    }

    public function testNoPathWhenTargetUnreachable(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('isolated'));
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $model->addTechnicalAsset($web);

        $isolated = $model->getTechnicalAsset('isolated');
        self::assertNotNull($isolated, 'isolated asset must exist in the model');
        self::assertSame([], $this->graph($model)->pathsFromInternet($isolated, maxHops: 4));
    }

    public function testFindsMultiplePathsFromDifferentInternetAssets(): void
    {
        $model = new ThreatModel('App');
        $webA = new TechnicalAsset('web-a');
        $webA->internet = true;
        $webA->communicatesTo('db');
        $webB = new TechnicalAsset('web-b');
        $webB->internet = true;
        $webB->communicatesTo('db');
        $model->addTechnicalAsset($webA)->addTechnicalAsset($webB)->addTechnicalAsset(new TechnicalAsset('db'));

        $db = $model->getTechnicalAsset('db');
        self::assertNotNull($db, 'db asset must exist in the model');
        $paths = $this->graph($model)->pathsFromInternet($db, maxHops: 4);
        self::assertCount(2, $paths);
    }

    public function testDoesNotLoopOnCycles(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('app');
        $app = new TechnicalAsset('app');
        $app->communicatesTo('web'); // cycle back
        $app->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($app)->addTechnicalAsset(new TechnicalAsset('db'));

        $db = $model->getTechnicalAsset('db');
        self::assertNotNull($db, 'db asset must exist in the model');
        $paths = $this->graph($model)->pathsFromInternet($db, maxHops: 10);
        self::assertCount(1, $paths, 'cycle must not produce infinite or duplicate paths');
    }
}
