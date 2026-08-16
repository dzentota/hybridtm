<?php
declare(strict_types=1);
namespace HybridTM\Tests\Risk;

use HybridTM\DSL\RiskTracking;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Risk\RiskDecision;
use PHPUnit\Framework\TestCase;

final class RiskDecisionTest extends TestCase
{
    private function validAccepted(): RiskDecision
    {
        return new RiskDecision(
            findingStableId: 'abc123',
            status: DecisionStatus::Accepted,
            justification: 'Compensating control already in place.',
            ticket: 'JIRA-1',
            expiresAt: new \DateTimeImmutable('2099-01-01'),
            decidedBy: 'Alice',
            decidedAt: new \DateTimeImmutable('2026-01-01'),
        );
    }

    public function testConstructsValidDecision(): void
    {
        $decision = $this->validAccepted();
        self::assertSame('abc123', $decision->findingStableId);
        self::assertSame(DecisionStatus::Accepted, $decision->status);
    }

    public function testAcceptedWithoutExpiryThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/expiresAt/');

        new RiskDecision(
            findingStableId: 'abc123',
            status: DecisionStatus::Accepted,
            justification: 'Compensating control already in place.',
            ticket: null,
            expiresAt: null,
            decidedBy: 'Alice',
            decidedAt: new \DateTimeImmutable('2026-01-01'),
        );
    }

    public function testDeferredWithoutExpiryThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RiskDecision(
            findingStableId: 'abc123',
            status: DecisionStatus::Deferred,
            justification: 'Needs follow-up after next release.',
            ticket: null,
            expiresAt: null,
            decidedBy: 'Alice',
            decidedAt: new \DateTimeImmutable('2026-01-01'),
        );
    }

    public function testMitigatedWithoutExpiryIsFine(): void
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
        self::assertNull($decision->expiresAt);
    }

    public function testShortJustificationThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/justification/');

        new RiskDecision(
            findingStableId: 'abc123',
            status: DecisionStatus::Mitigated,
            justification: 'fixed',
            ticket: null,
            expiresAt: null,
            decidedBy: 'Alice',
            decidedAt: new \DateTimeImmutable('2026-01-01'),
        );
    }

    public function testToRiskTrackingRoundTrips(): void
    {
        $decision = $this->validAccepted();
        $tracking = $decision->toRiskTracking();

        self::assertInstanceOf(RiskTracking::class, $tracking);
        self::assertSame('abc123', $tracking->syntheticRiskId);
        self::assertSame(DecisionStatus::Accepted, $tracking->status);
        self::assertSame('Compensating control already in place.', $tracking->justification);
        self::assertSame('JIRA-1', $tracking->ticket);
        self::assertSame('2099-01-01', $tracking->expiresAt);
        self::assertSame('Alice', $tracking->checkedBy);
        self::assertSame('2026-01-01', $tracking->date);
    }

    public function testFromRiskTrackingRoundTrips(): void
    {
        $tracking = new RiskTracking('abc123');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'Compensating control already in place.';
        $tracking->ticket = 'JIRA-1';
        $tracking->expiresAt = '2099-01-01';
        $tracking->checkedBy = 'Alice';
        $tracking->date = '2026-01-01';

        $decision = RiskDecision::fromRiskTracking($tracking);

        self::assertSame('abc123', $decision->findingStableId);
        self::assertSame(DecisionStatus::Accepted, $decision->status);
        self::assertEquals(new \DateTimeImmutable('2099-01-01'), $decision->expiresAt);
        self::assertEquals(new \DateTimeImmutable('2026-01-01'), $decision->decidedAt);
    }

    public function testFromRiskTrackingWithoutDateFallsBackToEpochNotWallClock(): void
    {
        $tracking = new RiskTracking('abc123');
        $tracking->justification = str_repeat('x', 25);

        $decision = RiskDecision::fromRiskTracking($tracking);
        self::assertEquals(new \DateTimeImmutable('@0'), $decision->decidedAt);
    }

    public function testFromRiskTrackingEmptyTicketBecomesNull(): void
    {
        $tracking = new RiskTracking('abc123');
        $tracking->justification = str_repeat('x', 25);

        self::assertNull(RiskDecision::fromRiskTracking($tracking)->ticket);
    }

    public function testRoundTripThroughBothDirectionsIsStable(): void
    {
        $decision = $this->validAccepted();
        $roundTripped = RiskDecision::fromRiskTracking($decision->toRiskTracking());

        self::assertSame($decision->findingStableId, $roundTripped->findingStableId);
        self::assertSame($decision->status, $roundTripped->status);
        self::assertSame($decision->justification, $roundTripped->justification);
        self::assertEquals($decision->expiresAt, $roundTripped->expiresAt);
        self::assertEquals($decision->decidedAt, $roundTripped->decidedAt);
    }
}
