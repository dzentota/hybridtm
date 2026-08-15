<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\Rules\GraphPath;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use PHPUnit\Framework\TestCase;

final class GraphPathTest extends TestCase
{
    public function testAnyNodeHasTraitChecksAllNodes(): void
    {
        $model = new ThreatModel('App');
        $waf = new TechnicalAsset('waf');
        $waf->traits = ['waf'];
        $app = new TechnicalAsset('app');
        $db = new TechnicalAsset('db');
        $model->addTechnicalAsset($waf)->addTechnicalAsset($app)->addTechnicalAsset($db);

        $path = new GraphPath(['waf', 'app', 'db'], $model, new DerivedTraits());

        self::assertTrue($path->anyNodeHasTrait('waf'));
        self::assertFalse($path->anyNodeHasTrait('ids'));
        self::assertTrue($path->anyNodeHasTrait('ids', 'waf'), 'OR semantics across the trait list');
    }

    public function testAnyNodeHasTraitChecksDerivedTraitsToo(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('app'));
        $derived = new DerivedTraits();
        $derived->add('app', 'behind_waf');

        $path = new GraphPath(['app'], $model, $derived);
        self::assertTrue($path->anyNodeHasTrait('behind_waf'));
    }

    public function testHopCount(): void
    {
        $model = new ThreatModel('App');
        $path = new GraphPath(['a', 'b', 'c'], $model, new DerivedTraits());
        self::assertSame(2, $path->hopCount());

        $trivial = new GraphPath(['a'], $model, new DerivedTraits());
        self::assertSame(0, $trivial->hopCount());
    }

    public function testDescribeUsesDisplayNames(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web', 'Web App'));
        $model->addTechnicalAsset(new TechnicalAsset('db', 'Database'));

        $path = new GraphPath(['web', 'db'], $model, new DerivedTraits());
        self::assertSame('Web App -> Database', $path->describe());
    }
}
