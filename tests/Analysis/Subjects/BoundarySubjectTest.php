<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis\Subjects;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\Subjects\BoundarySubject;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\TrustBoundaryType;
use PHPUnit\Framework\TestCase;

final class BoundarySubjectTest extends TestCase
{
    public function testExposesBasicFields(): void
    {
        $model = new ThreatModel('App');
        $boundary = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
        $boundary->addAssets('web');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $model->addTrustBoundary($boundary);

        $subject = new BoundarySubject($boundary, $model, new DerivedTraits());

        self::assertSame('dmz', $subject->id);
        self::assertSame('DMZ', $subject->name);
        self::assertSame('network-cloud-security-group', $subject->type);
        self::assertSame(['web'], $subject->technicalAssetIds);
        self::assertSame(1, $subject->assetCount());
    }

    public function testAnyAssetHasTrait(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $web = new TechnicalAsset('web');
        $model->addTechnicalAsset($db)->addTechnicalAsset($web);

        $boundary = new TrustBoundary('net');
        $boundary->addAssets('db', 'web');
        $model->addTrustBoundary($boundary);

        $subject = new BoundarySubject($boundary, $model, new DerivedTraits());

        self::assertTrue($subject->anyAssetHasTrait('datastore'));
        self::assertFalse($subject->anyAssetHasTrait('waf'));
    }
}
