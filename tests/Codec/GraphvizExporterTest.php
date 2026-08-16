<?php
declare(strict_types=1);
namespace HybridTM\Tests\Codec;

use HybridTM\Codec\GraphvizExporter;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\TrustBoundaryType;
use PHPUnit\Framework\TestCase;

final class GraphvizExporterTest extends TestCase
{
    private GraphvizExporter $exporter;

    protected function setUp(): void
    {
        $this->exporter = new GraphvizExporter();
    }

    public function testProducesABalancedDigraphBlock(): void
    {
        $out = $this->exporter->export(new ThreatModel('App'));

        self::assertStringStartsWith('digraph HybridTM {', $out);
        self::assertStringEndsWith("}\n", $out);
        self::assertSame(substr_count($out, '{'), substr_count($out, '}'));
    }

    public function testRendersBoundaryAsCluster(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web', 'Web Server'));
        $dmz = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
        $dmz->addAssets('web');
        $model->addTrustBoundary($dmz);

        $out = $this->exporter->export($model);

        self::assertStringContainsString('subgraph "cluster_dmz"', $out);
        self::assertStringContainsString('label="DMZ";', $out);
        self::assertStringContainsString('"web" [label="Web Server"];', $out);
    }

    public function testRendersCommunicationLinksAsLabeledEdges(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web', 'Web');
        $model->addTechnicalAsset($web);
        $model->addTechnicalAsset(new TechnicalAsset('db', 'DB'));
        $web->communicatesTo('db', Protocol::JdbcEncrypted);

        $out = $this->exporter->export($model);

        self::assertStringContainsString('"web" -> "db" [label="jdbc-encrypted"];', $out);
    }

    public function testEscapesDoubleQuotesInLabels(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web', 'The "Web" Server'));

        $out = $this->exporter->export($model);

        self::assertStringContainsString('label="The \\"Web\\" Server"', $out);
    }
}
