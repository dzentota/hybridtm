<?php
declare(strict_types=1);
namespace HybridTM\Tests\Codec;

use HybridTM\Codec\MermaidExporter;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\TrustBoundaryType;
use PHPUnit\Framework\TestCase;

final class MermaidExporterTest extends TestCase
{
    private MermaidExporter $exporter;

    protected function setUp(): void
    {
        $this->exporter = new MermaidExporter();
    }

    public function testStartsWithFlowchartDirective(): void
    {
        $out = $this->exporter->export(new ThreatModel('App'));

        self::assertStringStartsWith('flowchart LR', $out);
    }

    public function testRendersComponentsOutsideAnyBoundaryAtTopLevel(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web', 'Web Server'));

        $out = $this->exporter->export($model);

        self::assertStringContainsString('web["Web Server"]', $out);
        self::assertStringNotContainsString('subgraph', $out);
    }

    public function testGroupsBoundaryMembersInASubgraph(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web', 'Web Server'));
        $dmz = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
        $dmz->addAssets('web');
        $model->addTrustBoundary($dmz);

        $out = $this->exporter->export($model);

        self::assertStringContainsString('subgraph dmz["DMZ"]', $out);
        self::assertStringContainsString('web["Web Server"]', $out);
        self::assertStringContainsString('end', $out);
    }

    public function testRendersCommunicationLinksAsLabeledEdges(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web', 'Web');
        $model->addTechnicalAsset($web);
        $model->addTechnicalAsset(new TechnicalAsset('db', 'DB'));
        $web->communicatesTo('db', Protocol::JdbcEncrypted);

        $out = $this->exporter->export($model);

        self::assertStringContainsString('web -->|jdbc-encrypted| db', $out);
    }

    public function testSanitizesNonAlphanumericIdsForMermaid(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web-server.1', 'Web'));

        $out = $this->exporter->export($model);

        self::assertStringContainsString('web_server_1["Web"]', $out);
    }
}
