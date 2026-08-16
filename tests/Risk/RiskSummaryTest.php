<?php
declare(strict_types=1);
namespace HybridTM\Tests\Risk;

use HybridTM\Analysis\Finding;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Risk\RiskSummary;
use PHPUnit\Framework\TestCase;

final class RiskSummaryTest extends TestCase
{
    private function finding(Likelihood $likelihood, Impact $impact): Finding
    {
        return Finding::create(
            threatId: 'THREAT-X',
            ruleId: 'rule/x',
            subject: SubjectRef::component('x'),
            title: 'X',
            likelihood: $likelihood,
            impact: $impact,
        );
    }

    public function testEmptyFindingsProduceZeroedCounts(): void
    {
        $summary = RiskSummary::from([]);
        self::assertSame(0, $summary->total);
        self::assertSame(0, $summary->countsBySeverity['critical']);
    }

    public function testCountsBySeverity(): void
    {
        $findings = [
            $this->finding(Likelihood::Unlikely, Impact::Low), // low
            $this->finding(Likelihood::Frequent, Impact::VeryHigh), // critical
            $this->finding(Likelihood::Frequent, Impact::VeryHigh), // critical
        ];

        $summary = RiskSummary::from($findings);

        self::assertSame(3, $summary->total);
        self::assertSame(1, $summary->countsBySeverity['low']);
        self::assertSame(2, $summary->countsBySeverity['critical']);
        self::assertSame(0, $summary->countsBySeverity['medium']);
    }

    public function testJsonSerializeShape(): void
    {
        $summary = RiskSummary::from([$this->finding(Likelihood::Likely, Impact::Medium)]);
        $json = $summary->jsonSerialize();

        self::assertArrayHasKey('countsBySeverity', $json);
        self::assertArrayHasKey('total', $json);
        self::assertSame(1, $json['total']);
    }
}
