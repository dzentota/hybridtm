<?php

declare(strict_types=1);

namespace HybridTM\Tests\Risk;

use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Risk\ExpiredAcceptanceReverter;
use PHPUnit\Framework\TestCase;

final class ExpiredAcceptanceReverterTest extends TestCase
{
    private ExpiredAcceptanceReverter $reverter;

    protected function setUp(): void
    {
        $this->reverter = new ExpiredAcceptanceReverter();
    }

    public function testRevertsExpiredAcceptance(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->expiresAt = '2026-01-01';
        $model->addRiskTracking($tracking);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2026-01-02'));

        self::assertCount(1, $reverted);
        self::assertSame(DecisionStatus::Open, $tracking->status, 'the original object is mutated in place');
    }

    public function testDoesNotRevertUnexpiredAcceptance(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->expiresAt = '2026-01-01';
        $model->addRiskTracking($tracking);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2025-12-31'));

        self::assertSame([], $reverted);
        self::assertSame(DecisionStatus::Accepted, $tracking->status);
    }

    public function testExactExpiryMomentIsNotYetExpired(): void
    {
        // Boundary case: "now" equal to expiresAt is not "past" it.
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->expiresAt = '2026-01-01';
        $model->addRiskTracking($tracking);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2026-01-01T00:00:00'));

        self::assertSame([], $reverted);
        self::assertSame(DecisionStatus::Accepted, $tracking->status);
    }

    public function testOneSecondPastExpiryIsExpired(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->expiresAt = '2026-01-01';
        $model->addRiskTracking($tracking);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2026-01-01T00:00:01'));

        self::assertCount(1, $reverted);
    }

    public function testDoesNotTouchMitigatedOrFalsePositive(): void
    {
        $model = new ThreatModel('App');
        $mitigated = new RiskTracking('risk-1');
        $mitigated->status = DecisionStatus::Mitigated;
        $model->addRiskTracking($mitigated);

        $falsePositive = new RiskTracking('risk-2');
        $falsePositive->status = DecisionStatus::FalsePositive;
        $model->addRiskTracking($falsePositive);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2099-01-01'));

        self::assertSame([], $reverted);
    }

    public function testDoesNotTouchAcceptedWithoutExpiresAt(): void
    {
        // Shouldn't happen given RiskTrackingValidityRule, but the reverter
        // itself must not crash or misbehave on it either way.
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $model->addRiskTracking($tracking);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2099-01-01'));

        self::assertSame([], $reverted);
        self::assertSame(DecisionStatus::Accepted, $tracking->status);
    }

    public function testRevertsDeferredTooSinceItAlsoRequiresExpiry(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Deferred;
        $tracking->expiresAt = '2026-01-01';
        $model->addRiskTracking($tracking);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2026-06-01'));
        self::assertCount(1, $reverted);
        self::assertSame(DecisionStatus::Open, $tracking->status);
    }

    public function testRevertsMultipleIndependently(): void
    {
        $model = new ThreatModel('App');
        $expired = new RiskTracking('risk-1');
        $expired->status = DecisionStatus::Accepted;
        $expired->expiresAt = '2020-01-01';
        $model->addRiskTracking($expired);

        $notExpired = new RiskTracking('risk-2');
        $notExpired->status = DecisionStatus::Accepted;
        $notExpired->expiresAt = '2099-01-01';
        $model->addRiskTracking($notExpired);

        $reverted = $this->reverter->revertExpired($model, new \DateTimeImmutable('2026-01-01'));

        self::assertCount(1, $reverted);
        self::assertSame('risk-1', $reverted[0]->syntheticRiskId);
        self::assertSame(DecisionStatus::Accepted, $notExpired->status);
    }
}
