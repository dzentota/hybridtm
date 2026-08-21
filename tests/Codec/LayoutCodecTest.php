<?php

declare(strict_types=1);

namespace HybridTM\Tests\Codec;

use HybridTM\Codec\Layout\EdgeLayout;
use HybridTM\Codec\Layout\GroupLayout;
use HybridTM\Codec\Layout\ModelLayout;
use HybridTM\Codec\Layout\NodeLayout;
use HybridTM\Codec\Layout\Viewport;
use HybridTM\Codec\LayoutCodec;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use PHPUnit\Framework\TestCase;

final class LayoutCodecTest extends TestCase
{
    private LayoutCodec $codec;
    private string $tmpFile;

    protected function setUp(): void
    {
        $this->codec = new LayoutCodec();
        $this->tmpFile = sys_get_temp_dir() . '/hybridtm_layout_' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tmpFile)) {
            unlink($this->tmpFile);
        }
    }

    // ── encode/decode ────────────────────────────────────────────────────────

    public function testEncodesSchemaVersion(): void
    {
        $encoded = $this->codec->encode(new ModelLayout());
        self::assertSame(1, $encoded['schemaVersion']);
    }

    public function testRoundTripsNodesGroupsEdgesAndViewport(): void
    {
        $layout = new ModelLayout(
            nodes: ['web' => new NodeLayout(x: 100, y: 50, w: 220, h: 96)],
            groups: ['dmz' => new GroupLayout(x: 40, y: 10, w: 400, h: 300, collapsed: true)],
            edges: ['web-to-db' => new EdgeLayout([[460.0, 168.0], [520.0, 168.0]])],
            viewport: new Viewport(x: 10, y: 20, zoom: 1.5),
        );

        $decoded = $this->codec->decode(json_decode(json_encode($this->codec->encode($layout), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR));

        self::assertEquals(100.0, $decoded->nodes['web']->x);
        self::assertEquals(50.0, $decoded->nodes['web']->y);
        self::assertTrue($decoded->groups['dmz']->collapsed);
        self::assertEquals(400.0, $decoded->groups['dmz']->w);
        self::assertSame([[460.0, 168.0], [520.0, 168.0]], $decoded->edges['web-to-db']->waypoints);
        self::assertEquals(1.5, $decoded->viewport->zoom);
    }

    public function testDecodeToleratesMissingSections(): void
    {
        $decoded = $this->codec->decode(['schemaVersion' => 1]);

        self::assertSame([], $decoded->nodes);
        self::assertSame([], $decoded->groups);
        self::assertSame([], $decoded->edges);
        self::assertEquals(0.0, $decoded->viewport->x);
        self::assertEquals(1.0, $decoded->viewport->zoom);
    }

    // ── default generation ───────────────────────────────────────────────────

    public function testGenerateDefaultPlacesNodesInAGrid(): void
    {
        $model = new ThreatModel('App');
        for ($i = 0; $i < 5; $i++) {
            $model->addTechnicalAsset(new TechnicalAsset("asset-{$i}"));
        }

        $layout = $this->codec->generateDefault($model);

        self::assertCount(5, $layout->nodes);
        // 4 columns: asset-0..3 on row 0, asset-4 wraps to row 1.
        self::assertEquals(0.0, $layout->nodes['asset-0']->y);
        self::assertEquals($layout->nodes['asset-0']->y, $layout->nodes['asset-3']->y);
        self::assertGreaterThan($layout->nodes['asset-3']->y, $layout->nodes['asset-4']->y);
        self::assertNotEquals($layout->nodes['asset-0']->x, $layout->nodes['asset-1']->x);
    }

    public function testGenerateDefaultProducesNoOverlappingColumns(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('a'));
        $model->addTechnicalAsset(new TechnicalAsset('b'));

        $layout = $this->codec->generateDefault($model);

        self::assertGreaterThanOrEqual(
            $layout->nodes['a']->x + $layout->nodes['a']->w,
            $layout->nodes['b']->x,
        );
    }

    public function testGenerateDefaultBuildsGroupBoundingBoxAroundContainedAssets(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $model->addTechnicalAsset(new TechnicalAsset('db'));
        $boundary = new TrustBoundary('net');
        $boundary->addAssets('web', 'db');
        $model->addTrustBoundary($boundary);

        $layout = $this->codec->generateDefault($model);

        self::assertArrayHasKey('net', $layout->groups);
        $group = $layout->groups['net'];
        $web = $layout->nodes['web'];
        $db = $layout->nodes['db'];

        self::assertLessThanOrEqual($web->x, $group->x);
        self::assertLessThanOrEqual($db->x, $group->x);
        self::assertGreaterThanOrEqual($web->x + $web->w, $group->x + $group->w);
        self::assertGreaterThanOrEqual($db->x + $db->w, $group->x + $group->w);
    }

    public function testGenerateDefaultSkipsEmptyBoundary(): void
    {
        $model = new ThreatModel('App');
        $model->addTrustBoundary(new TrustBoundary('empty'));

        $layout = $this->codec->generateDefault($model);
        self::assertArrayNotHasKey('empty', $layout->groups);
    }

    // ── loadOrGenerate ───────────────────────────────────────────────────────

    public function testLoadOrGenerateFallsBackWhenFileMissing(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        $layout = $this->codec->loadOrGenerate($this->tmpFile . '.does-not-exist', $model);
        self::assertArrayHasKey('web', $layout->nodes);
    }

    public function testLoadOrGenerateReadsExistingFile(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        file_put_contents($this->tmpFile, json_encode([
            'schemaVersion' => 1,
            'nodes' => ['web' => ['x' => 999, 'y' => 888, 'w' => 220, 'h' => 96]],
            'groups' => [],
            'edges' => [],
            'viewport' => ['x' => 0, 'y' => 0, 'zoom' => 1],
        ], JSON_THROW_ON_ERROR));

        $layout = $this->codec->loadOrGenerate($this->tmpFile, $model);
        self::assertEquals(999.0, $layout->nodes['web']->x);
    }

    public function testLoadOrGenerateFallsBackOnCorruptFile(): void
    {
        file_put_contents($this->tmpFile, 'not json {{{');
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        $layout = $this->codec->loadOrGenerate($this->tmpFile, $model);
        self::assertArrayHasKey('web', $layout->nodes);
    }
}
