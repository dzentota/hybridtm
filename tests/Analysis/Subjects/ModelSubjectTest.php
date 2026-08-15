<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis\Subjects;

use HybridTM\Analysis\Subjects\ModelSubject;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\BusinessCriticality;
use PHPUnit\Framework\TestCase;

final class ModelSubjectTest extends TestCase
{
    public function testExposesBasicFields(): void
    {
        $model = new ThreatModel('My App');
        $model->businessCriticality = BusinessCriticality::MissionCritical;
        $model->addTechnicalAsset(new TechnicalAsset('a'));
        $model->addTechnicalAsset(new TechnicalAsset('b'));
        $model->addTrustBoundary(new TrustBoundary('net'));

        $subject = new ModelSubject($model);

        self::assertSame('My App', $subject->title);
        self::assertSame('mission-critical', $subject->businessCriticality);
        self::assertSame(2, $subject->technicalAssetCount);
        self::assertSame(1, $subject->trustBoundaryCount);
    }
}
