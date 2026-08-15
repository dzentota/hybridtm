<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\DeriveEngine;
use HybridTM\Analysis\ModelIndex;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use PHPUnit\Framework\TestCase;

final class DeriveEngineTest extends TestCase
{
    private function derive(ThreatModel $model): \HybridTM\Analysis\DerivedTraits
    {
        return (new DeriveEngine())->derive($model, ModelIndex::build($model));
    }

    public function testInternetReachableSeedsFromInternetFacingAssets(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $model->addTechnicalAsset($web);

        $derived = $this->derive($model);
        self::assertContains('internet_reachable', $derived->forAsset('web'));
    }

    public function testInternetReachablePropagatesAlongOutgoingLinks(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('app');
        $app = new TechnicalAsset('app');
        $app->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($app)->addTechnicalAsset(new TechnicalAsset('db'));

        $derived = $this->derive($model);
        self::assertContains('internet_reachable', $derived->forAsset('app'));
        self::assertContains('internet_reachable', $derived->forAsset('db'));
    }

    public function testInternetReachableDoesNotFlowBackwards(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('isolated'));
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $model->addTechnicalAsset($web);

        $derived = $this->derive($model);
        self::assertSame([], $derived->forAsset('isolated'));
    }

    public function testStoresPiiRequiresPiiTaggedDataAsset(): void
    {
        $model = new ThreatModel('App');
        $pii = new DataAsset('email');
        $pii->tags = ['pii'];
        $model->addDataAsset($pii);
        $model->addDataAsset(new DataAsset('metrics'));

        $db = new TechnicalAsset('db');
        $db->dataAssetsStored = ['email'];
        $other = new TechnicalAsset('other');
        $other->dataAssetsStored = ['metrics'];
        $model->addTechnicalAsset($db)->addTechnicalAsset($other);

        $derived = $this->derive($model);
        self::assertContains('stores_pii', $derived->forAsset('db'));
        self::assertNotContains('stores_pii', $derived->forAsset('other'));
    }

    public function testHandlesStrictlyConfidential(): void
    {
        $model = new ThreatModel('App');
        $secret = new DataAsset('secret');
        $secret->confidentiality = \HybridTM\Enums\Confidentiality::StrictlyConfidential;
        $model->addDataAsset($secret);

        $asset = new TechnicalAsset('vault');
        $asset->dataAssetsProcessed = ['secret'];
        $model->addTechnicalAsset($asset);

        self::assertContains('handles_strictly_confidential', $this->derive($model)->forAsset('vault'));
    }

    public function testSinglePointOfFailureRequiresNonRedundantAndHighInDegree(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->redundant = false;
        $model->addTechnicalAsset($db);
        foreach (['a', 'b', 'c'] as $callerId) {
            $caller = new TechnicalAsset($callerId);
            $caller->communicatesTo('db');
            $model->addTechnicalAsset($caller);
        }

        self::assertContains('single_point_of_failure', $this->derive($model)->forAsset('db'));
    }

    public function testSinglePointOfFailureNotFlaggedWhenRedundant(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->redundant = true;
        $model->addTechnicalAsset($db);
        foreach (['a', 'b', 'c'] as $callerId) {
            $caller = new TechnicalAsset($callerId);
            $caller->communicatesTo('db');
            $model->addTechnicalAsset($caller);
        }

        self::assertNotContains('single_point_of_failure', $this->derive($model)->forAsset('db'));
    }

    public function testDirectlyExposedDatastore(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        self::assertContains('directly_exposed_datastore', $this->derive($model)->forAsset('db'));
    }

    public function testDatastoreNotExposedWhenAccessedViaInternalAssetOnly(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $app = new TechnicalAsset('app'); // not internet-facing
        $app->communicatesTo('db');
        $model->addTechnicalAsset($app)->addTechnicalAsset($db);

        self::assertNotContains('directly_exposed_datastore', $this->derive($model)->forAsset('db'));
    }

    public function testBehindWafDetectsAncestorWithWafTrait(): void
    {
        $model = new ThreatModel('App');
        $waf = new TechnicalAsset('waf');
        $waf->traits = ['waf'];
        $waf->communicatesTo('app');
        $app = new TechnicalAsset('app');
        $model->addTechnicalAsset($waf)->addTechnicalAsset($app);

        self::assertContains('behind_waf', $this->derive($model)->forAsset('app'));
    }

    public function testNotBehindWafWithoutOne(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('app');
        $app = new TechnicalAsset('app');
        $model->addTechnicalAsset($web)->addTechnicalAsset($app);

        self::assertNotContains('behind_waf', $this->derive($model)->forAsset('app'));
    }
}
