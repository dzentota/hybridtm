<?php
declare(strict_types=1);
namespace HybridTM\Tests\Codec;

use HybridTM\Codec\OtmCodec;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Technology;
use PHPUnit\Framework\TestCase;

final class OtmCodecTest extends TestCase
{
    private OtmCodec $codec;

    protected function setUp(): void
    {
        $this->codec = new OtmCodec();
    }

    // ── export ───────────────────────────────────────────────────────────────

    public function testExportsOtmVersionAndProject(): void
    {
        $model = new ThreatModel('My App');
        $model->description = 'desc';

        $otm = $this->codec->export($model);

        self::assertSame('0.2.0', $otm['otmVersion']);
        self::assertSame('My App', $otm['project']['name']);
        self::assertSame('desc', $otm['project']['description']);
        self::assertSame('my-app', $otm['project']['id']);
    }

    public function testExportsComponentsWithDefaultTrustZoneWhenNoBoundary(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web', 'Web'));

        $otm = $this->codec->export($model);

        self::assertCount(1, $otm['components']);
        self::assertSame('web', $otm['components'][0]['id']);
        self::assertSame('default', $otm['components'][0]['parent']['trustZone']);
        self::assertContains(['id' => 'default', 'name' => 'Default', 'risk' => ['trustRating' => 50]], $otm['trustZones']);
    }

    public function testExportsComponentParentAsItsTrustBoundary(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $dmz = new TrustBoundary('dmz', 'DMZ');
        $dmz->addAssets('web');
        $model->addTrustBoundary($dmz);

        $otm = $this->codec->export($model);
        self::assertSame('dmz', $otm['components'][0]['parent']['trustZone']);
    }

    public function testExportsNestedTrustZoneParent(): void
    {
        $model = new ThreatModel('App');
        $outer = new TrustBoundary('outer');
        $outer->trustBoundariesNested = ['inner'];
        $inner = new TrustBoundary('inner');
        $model->addTrustBoundary($outer)->addTrustBoundary($inner);

        $otm = $this->codec->export($model);

        $innerZone = current(array_filter($otm['trustZones'], static fn ($z) => $z['id'] === 'inner'));
        self::assertSame('outer', $innerZone['parent']['trustZone']);
    }

    public function testExportsDataflows(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db');
        $link->description = 'reads user data';
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $otm = $this->codec->export($model);

        self::assertCount(1, $otm['dataflows']);
        self::assertSame('web', $otm['dataflows'][0]['source']);
        self::assertSame('db', $otm['dataflows'][0]['destination']);
        self::assertSame('reads user data', $otm['dataflows'][0]['name']);
    }

    // ── import ───────────────────────────────────────────────────────────────

    public function testImportsProjectAndComponents(): void
    {
        $model = $this->codec->import([
            'otmVersion' => '0.2.0',
            'project' => ['id' => 'app', 'name' => 'Imported App', 'description' => 'from OTM'],
            'trustZones' => [['id' => 'dmz', 'name' => 'DMZ', 'risk' => ['trustRating' => 10]]],
            'components' => [
                ['id' => 'web', 'name' => 'Web', 'type' => 'web-service-rest', 'parent' => ['trustZone' => 'dmz']],
            ],
            'dataflows' => [],
        ]);

        self::assertSame('Imported App', $model->title);
        self::assertSame('from OTM', $model->description);
        self::assertSame(Technology::WebServiceRest, $model->getTechnicalAsset('web')->technology);
        self::assertSame(['web'], $model->getTrustBoundaries()['dmz']->technicalAssetsInside);
    }

    public function testImportsUnknownComponentTypeAsUnknownTechnology(): void
    {
        $model = $this->codec->import([
            'project' => ['name' => 'App'],
            'components' => [['id' => 'thing', 'name' => 'Thing', 'type' => 'some-otm-only-type']],
        ]);

        self::assertSame(Technology::Unknown, $model->getTechnicalAsset('thing')->technology);
    }

    public function testImportsNestedTrustZones(): void
    {
        $model = $this->codec->import([
            'project' => ['name' => 'App'],
            'trustZones' => [
                ['id' => 'outer', 'name' => 'Outer'],
                ['id' => 'inner', 'name' => 'Inner', 'parent' => ['trustZone' => 'outer']],
            ],
            'components' => [],
        ]);

        self::assertSame(['inner'], $model->getTrustBoundaries()['outer']->trustBoundariesNested);
    }

    public function testImportsDataflowAsCommunicationLink(): void
    {
        $model = $this->codec->import([
            'project' => ['name' => 'App'],
            'components' => [
                ['id' => 'web', 'name' => 'Web'],
                ['id' => 'db', 'name' => 'DB'],
            ],
            'dataflows' => [
                ['id' => 'f1', 'name' => 'reads data', 'source' => 'web', 'destination' => 'db'],
            ],
        ]);

        $link = $model->getTechnicalAsset('web')->communicationLinks['web-to-db'];
        self::assertSame('db', $link->targetAssetId);
        self::assertSame('reads data', $link->description);
    }

    public function testDefaultTrustZoneIsNotImportedAsARealBoundary(): void
    {
        $model = $this->codec->import([
            'project' => ['name' => 'App'],
            'trustZones' => [['id' => 'default', 'name' => 'Default']],
            'components' => [['id' => 'web', 'name' => 'Web', 'parent' => ['trustZone' => 'default']]],
        ]);

        self::assertSame([], $model->getTrustBoundaries());
    }

    // ── round trip ───────────────────────────────────────────────────────────

    public function testExportThenImportRoundTripsStructure(): void
    {
        $model = new ThreatModel('E-Commerce');
        $web = new TechnicalAsset('web', 'Web App');
        $web->technology = Technology::WebServiceRest;
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db', 'Database'));
        $dmz = new TrustBoundary('dmz', 'DMZ');
        $dmz->addAssets('web');
        $model->addTrustBoundary($dmz);

        $reimported = $this->codec->import($this->codec->export($model));

        self::assertSame('E-Commerce', $reimported->title);
        self::assertCount(2, $reimported->getTechnicalAssets());
        self::assertSame(Technology::WebServiceRest, $reimported->getTechnicalAsset('web')->technology);
        self::assertSame(['web'], $reimported->getTrustBoundaries()['dmz']->technicalAssetsInside);
        self::assertArrayHasKey('web-to-db', $reimported->getTechnicalAsset('web')->communicationLinks);
    }
}
