<?php
declare(strict_types=1);
namespace HybridTM\Tests\Validation;

use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\ValidationSeverity;
use HybridTM\Validation\ModelValidator;
use HybridTM\Validation\ValidatorRegistry;
use PHPUnit\Framework\TestCase;

final class ModelValidatorTest extends TestCase
{
    public function testCleanModelProducesNoIssues(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        $report = (new ModelValidator())->validate($model);

        self::assertCount(0, $report);
        self::assertFalse($report->hasErrors());
    }

    public function testAggregatesIssuesAcrossRules(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('unused'));
        $web = new TechnicalAsset('WEB'); // invalid slug
        $web->communicatesTo('ghost'); // dangling target
        $model->addTechnicalAsset($web);

        $report = (new ModelValidator())->validate($model);

        self::assertTrue($report->hasErrors());
        self::assertGreaterThanOrEqual(3, count($report->all()));
        self::assertNotEmpty($report->bySeverity(ValidationSeverity::Error));
        self::assertNotEmpty($report->bySeverity(ValidationSeverity::Info));
    }

    public function testDefaultRegistryHasTwelveRules(): void
    {
        self::assertCount(12, ValidatorRegistry::default()->all());
    }

    public function testCustomRegistryIsRespected(): void
    {
        $validator = new ModelValidator(new ValidatorRegistry());
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('unused'));

        $report = $validator->validate($model);

        self::assertCount(0, $report, 'an empty registry runs no checks');
    }
}
