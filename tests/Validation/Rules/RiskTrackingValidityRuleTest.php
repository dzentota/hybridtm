<?php
declare(strict_types=1);
namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Validation\Rules\RiskTrackingValidityRule;
use PHPUnit\Framework\TestCase;

final class RiskTrackingValidityRuleTest extends TestCase
{
    private RiskTrackingValidityRule $rule;

    protected function setUp(): void
    {
        $this->rule = new RiskTrackingValidityRule();
    }

    public function testOpenStatusWithNoJustificationIsFine(): void
    {
        $model = new ThreatModel('App');
        $model->addRiskTracking(new RiskTracking('risk-1')); // status defaults to Open, justification ''

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testAcceptedWithoutExpiresAtIsRejected(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'Compensating control in place already.';
        $model->addRiskTracking($tracking);

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
        self::assertStringContainsString('expiresAt', $issues[0]->message);
    }

    public function testDeferredWithoutExpiresAtIsRejected(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Deferred;
        $tracking->justification = 'Needs follow-up after the next release.';
        $model->addRiskTracking($tracking);

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testAcceptedWithExpiresAtAndJustificationPasses(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'Compensating control in place already.';
        $tracking->expiresAt = '2099-01-01';
        $model->addRiskTracking($tracking);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testMitigatedWithShortJustificationIsRejected(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Mitigated;
        $tracking->justification = 'fixed';
        $model->addRiskTracking($tracking);

        $issues = iterator_to_array($this->rule->check($model, null));
        self::assertCount(1, $issues);
        self::assertStringContainsString('justification', $issues[0]->message);
    }

    public function testMitigatedWithLongJustificationPasses(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Mitigated;
        $tracking->justification = 'Encryption at rest was enabled in production.';
        $model->addRiskTracking($tracking);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testFalsePositiveWithShortJustificationIsRejected(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::FalsePositive;
        $tracking->justification = 'no';
        $model->addRiskTracking($tracking);

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testBothProblemsOnSameEntryYieldTwoIssues(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('risk-1');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'short';
        $model->addRiskTracking($tracking);

        self::assertCount(2, iterator_to_array($this->rule->check($model, null)));
    }
}
