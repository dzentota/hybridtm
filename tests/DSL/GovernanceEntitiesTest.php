<?php
declare(strict_types=1);
namespace HybridTM\Tests\DSL;

use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\IndividualRiskCategory;
use HybridTM\DSL\Question;
use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\SecurityRequirement;
use HybridTM\DSL\SharedRuntime;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\RiskFunction;
use PHPUnit\Framework\TestCase;

final class GovernanceEntitiesTest extends TestCase
{
    public function testQuestionDefaults(): void
    {
        $q = new Question('q1', 'Was a pentest performed?');
        self::assertSame('q1', $q->id);
        self::assertNull($q->answer);
    }

    public function testAbuseCaseDefaults(): void
    {
        $case = new AbuseCase('c1');
        self::assertSame('', $case->description);
    }

    public function testSecurityRequirementDefaults(): void
    {
        $req = new SecurityRequirement('r1');
        self::assertSame('', $req->description);
    }

    public function testSharedRuntimeNameDefaultsToId(): void
    {
        $runtime = new SharedRuntime('node-1');
        self::assertSame('node-1', $runtime->name);
    }

    public function testSharedRuntimeAddAssetsNoDuplicates(): void
    {
        $runtime = new SharedRuntime('node-1');
        $runtime->addAssets('web', 'web', 'worker');
        self::assertCount(2, $runtime->technicalAssetsRunning);
    }

    public function testIndividualRiskCategoryDefaults(): void
    {
        $category = new IndividualRiskCategory('custom-risk');
        self::assertSame(RiskFunction::Operations, $category->function);
        self::assertSame([], $category->stride);
        self::assertSame([], $category->cwe);
    }

    public function testRiskTrackingDefaults(): void
    {
        $tracking = new RiskTracking('risk@asset');
        self::assertSame(DecisionStatus::Open, $tracking->status);
        self::assertNull($tracking->expiresAt);
    }

    public function testThreatModelWiresAllSixCollections(): void
    {
        $model = new ThreatModel('App');
        $model
            ->addQuestion(new Question('q1', 'text'))
            ->addAbuseCase(new AbuseCase('c1'))
            ->addSecurityRequirement(new SecurityRequirement('r1'))
            ->addSharedRuntime(new SharedRuntime('n1'))
            ->addIndividualRiskCategory(new IndividualRiskCategory('rc1'))
            ->addRiskTracking(new RiskTracking('rt1'));

        self::assertArrayHasKey('q1', $model->getQuestions());
        self::assertArrayHasKey('c1', $model->getAbuseCases());
        self::assertArrayHasKey('r1', $model->getSecurityRequirements());
        self::assertArrayHasKey('n1', $model->getSharedRuntimes());
        self::assertArrayHasKey('rc1', $model->getIndividualRiskCategories());
        self::assertArrayHasKey('rt1', $model->getRiskTracking());
    }
}
