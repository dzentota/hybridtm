<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\ModelIndex;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Protocol;
use PHPUnit\Framework\TestCase;

final class ModelIndexTest extends TestCase
{
    public function testAssetsWithTraitGroupsByTrait(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'sql_engine'];
        $cache = new TechnicalAsset('cache');
        $cache->traits = ['datastore'];
        $web = new TechnicalAsset('web');
        $model->addTechnicalAsset($db)->addTechnicalAsset($cache)->addTechnicalAsset($web);

        $index = ModelIndex::build($model);

        self::assertSame(['db', 'cache'], $index->assetsWithTrait('datastore'));
        self::assertSame(['db'], $index->assetsWithTrait('sql_engine'));
        self::assertSame([], $index->assetsWithTrait('nonexistent'));
    }

    public function testOutgoingAndIncomingLinks(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $db = new TechnicalAsset('db');
        $web->communicatesTo('db', Protocol::SqlAccessProtocol);
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        $index = ModelIndex::build($model);

        $outgoing = $index->outgoingLinks('web');
        self::assertCount(1, $outgoing);
        self::assertSame('web', $outgoing[0]->sourceAssetId);
        self::assertSame('db', $outgoing[0]->targetAssetId);

        $incoming = $index->incomingLinks('db');
        self::assertCount(1, $incoming);
        self::assertSame($outgoing[0]->link, $incoming[0]->link);

        self::assertSame([], $index->outgoingLinks('db'), 'db has no outgoing links');
        self::assertSame([], $index->incomingLinks('web'), 'web has no incoming links');
    }

    public function testMultipleIncomingLinksToSameTarget(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $worker = new TechnicalAsset('worker');
        $db = new TechnicalAsset('db');
        $web->communicatesTo('db');
        $worker->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($worker)->addTechnicalAsset($db);

        $index = ModelIndex::build($model);

        $incoming = $index->incomingLinks('db');
        self::assertCount(2, $incoming);
        self::assertSame(['web', 'worker'], array_map(static fn ($l) => $l->sourceAssetId, $incoming));
    }

    public function testBoundaryOf(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $model->addTechnicalAsset(new TechnicalAsset('db'));
        $boundary = new TrustBoundary('dmz');
        $boundary->addAssets('web');
        $model->addTrustBoundary($boundary);

        $index = ModelIndex::build($model);

        self::assertSame('dmz', $index->boundaryOf('web'));
        self::assertNull($index->boundaryOf('db'));
        self::assertNull($index->boundaryOf('nonexistent'));
    }

    public function testDataAssetUsageCoversProcessedAndStored(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('customer-pii'));

        $web = new TechnicalAsset('web');
        $web->dataAssetsProcessed = ['customer-pii'];
        $db = new TechnicalAsset('db');
        $db->dataAssetsStored = ['customer-pii'];
        $unrelated = new TechnicalAsset('other');
        $model->addTechnicalAsset($web)->addTechnicalAsset($db)->addTechnicalAsset($unrelated);

        $index = ModelIndex::build($model);

        self::assertSame(['web', 'db'], $index->assetsUsingDataAsset('customer-pii'));
        self::assertSame([], $index->assetsUsingDataAsset('nonexistent'));
    }

    public function testDataAssetUsageDoesNotDuplicateWhenBothProcessedAndStored(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('db');
        $asset->dataAssetsProcessed = ['customer-pii'];
        $asset->dataAssetsStored = ['customer-pii'];
        $model->addTechnicalAsset($asset);

        $index = ModelIndex::build($model);

        self::assertSame(['db'], $index->assetsUsingDataAsset('customer-pii'));
    }

    public function testEmptyModelProducesEmptyLookups(): void
    {
        $index = ModelIndex::build(new ThreatModel('Empty'));

        self::assertSame([], $index->assetsWithTrait('datastore'));
        self::assertSame([], $index->outgoingLinks('anything'));
        self::assertNull($index->boundaryOf('anything'));
        self::assertSame([], $index->assetsUsingDataAsset('anything'));
    }

    public function testBuildsLargeModelWithinPerformanceBudget(): void
    {
        // DoD (T-1.7): index construction for 500 nodes stays well under a
        // rule-engine-per-request budget. The plan's target is <20ms on
        // reference hardware; assert a generous multiple to keep CI stable.
        $model = new ThreatModel('Large');
        for ($i = 0; $i < 500; $i++) {
            $asset = new TechnicalAsset("asset-{$i}");
            $asset->traits = ['datastore'];
            if ($i > 0) {
                $asset->communicatesTo('asset-' . ($i - 1));
            }
            $model->addTechnicalAsset($asset);
        }

        $start = hrtime(true);
        $index = ModelIndex::build($model);
        $elapsedMs = (hrtime(true) - $start) / 1_000_000;

        self::assertCount(500, $index->assetsWithTrait('datastore'));
        self::assertLessThan(200, $elapsedMs, 'ModelIndex::build should stay fast on a 500-node model');
    }
}
