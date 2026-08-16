<?php
declare(strict_types=1);
namespace HybridTM\Tests\Risk;

use HybridTM\Analysis\Finding;
use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Risk\RiskDecision;
use HybridTM\Risk\RiskRegister;
use PHPUnit\Framework\TestCase;

final class RiskRegisterTest extends TestCase
{
    private function finding(string $subjectId): Finding
    {
        return Finding::create(
            threatId: 'THREAT-X',
            ruleId: 'rule/x',
            subject: SubjectRef::component($subjectId),
            title: 'X',
            likelihood: Likelihood::Likely,
            impact: Impact::Medium,
        );
    }

    public function testBuildComputesSummaryAndCoverage(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $model->addTechnicalAsset(new TechnicalAsset('db'));

        $findings = [$this->finding('web')];
        $register = RiskRegister::build($findings, [], $model);

        self::assertSame(1, $register->summary->total);
        self::assertSame(1, $register->coverage['coveredAssets']);
        self::assertSame(2, $register->coverage['totalAssets']);
        self::assertSame(50.0, $register->coverage['percentage']);
    }

    public function testCoverageIsZeroForEmptyModel(): void
    {
        $register = RiskRegister::build([], [], new ThreatModel('App'));
        self::assertSame(['coveredAssets' => 0, 'totalAssets' => 0, 'percentage' => 0.0], $register->coverage);
    }

    public function testCoverageDoesNotDoubleCountSameAssetTwice(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        $findings = [$this->finding('web'), $this->finding('web')];
        $register = RiskRegister::build($findings, [], $model);

        self::assertSame(1, $register->coverage['coveredAssets']);
    }

    public function testFullCoverageIsOneHundredPercent(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        $register = RiskRegister::build([$this->finding('web')], [], $model);
        self::assertSame(100.0, $register->coverage['percentage']);
    }

    public function testDecisionForFindsMatchingDecision(): void
    {
        $decision = new RiskDecision(
            findingStableId: 'abc123',
            status: DecisionStatus::Mitigated,
            justification: 'Encryption at rest was enabled.',
            ticket: null,
            expiresAt: null,
            decidedBy: 'Alice',
            decidedAt: new \DateTimeImmutable('2026-01-01'),
        );

        $register = RiskRegister::build([], [$decision], new ThreatModel('App'));

        self::assertSame($decision, $register->decisionFor('abc123'));
        self::assertNull($register->decisionFor('nonexistent'));
    }
}
