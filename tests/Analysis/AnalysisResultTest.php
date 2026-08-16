<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\AnalysisResult;
use HybridTM\Analysis\AnalysisStats;
use HybridTM\Analysis\Finding;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Severity;
use HybridTM\Validation\ValidationReport;
use PHPUnit\Framework\TestCase;

final class AnalysisResultTest extends TestCase
{
    private function finding(Severity $severity): Finding
    {
        [$likelihood, $impact] = match ($severity) {
            Severity::Low => [Likelihood::Unlikely, Impact::Low],
            Severity::Medium => [Likelihood::Likely, Impact::Low],
            Severity::Elevated => [Likelihood::Likely, Impact::Medium],
            Severity::High => [Likelihood::VeryLikely, Impact::High],
            Severity::Critical => [Likelihood::Frequent, Impact::VeryHigh],
        };

        return Finding::create('THREAT-X', 'rule/x', SubjectRef::component('db'), 'X', $likelihood, $impact);
    }

    public function testCountsBySeverityStartsAllZeroAndCountsEachFinding(): void
    {
        $result = new AnalysisResult(
            [$this->finding(Severity::Low), $this->finding(Severity::Low), $this->finding(Severity::Critical)],
            new ValidationReport(),
            new AnalysisStats(),
            'hash',
        );

        $counts = $result->countsBySeverity();

        self::assertSame(2, $counts['low']);
        self::assertSame(0, $counts['medium']);
        self::assertSame(0, $counts['elevated']);
        self::assertSame(0, $counts['high']);
        self::assertSame(1, $counts['critical']);
        self::assertSame(array_map(static fn ($s) => $s->value, Severity::cases()), array_keys($counts));
    }

    public function testCountsBySeverityIsZeroForEveryLevelOnNoFindings(): void
    {
        $result = new AnalysisResult([], new ValidationReport(), new AnalysisStats(), 'hash');

        foreach ($result->countsBySeverity() as $count) {
            self::assertSame(0, $count);
        }
    }

    public function testAtLeastFiltersByThreshold(): void
    {
        $low = $this->finding(Severity::Low);
        $high = $this->finding(Severity::High);
        $result = new AnalysisResult([$low, $high], new ValidationReport(), new AnalysisStats(), 'hash');

        $atLeastElevated = $result->atLeast(Severity::Elevated);

        self::assertSame([$high], $atLeastElevated);
    }

    public function testAtLeastIncludesExactMatchOfThreshold(): void
    {
        $medium = $this->finding(Severity::Medium);
        $result = new AnalysisResult([$medium], new ValidationReport(), new AnalysisStats(), 'hash');

        self::assertSame([$medium], $result->atLeast(Severity::Medium));
    }

    public function testHighestSeverityIsNullWhenNoFindings(): void
    {
        $result = new AnalysisResult([], new ValidationReport(), new AnalysisStats(), 'hash');

        self::assertNull($result->highestSeverity());
    }

    public function testHighestSeverityPicksTheMaximum(): void
    {
        $result = new AnalysisResult(
            [$this->finding(Severity::Low), $this->finding(Severity::Critical), $this->finding(Severity::Medium)],
            new ValidationReport(),
            new AnalysisStats(),
            'hash',
        );

        self::assertSame(Severity::Critical, $result->highestSeverity());
    }

    public function testJsonSerializeIncludesAllTopLevelKeys(): void
    {
        $result = new AnalysisResult([$this->finding(Severity::Low)], new ValidationReport(), new AnalysisStats(), 'the-hash');

        $json = $result->jsonSerialize();

        self::assertSame('the-hash', $json['inputHash']);
        self::assertCount(1, $json['findings']);
        self::assertInstanceOf(ValidationReport::class, $json['validation']);
        self::assertInstanceOf(AnalysisStats::class, $json['stats']);
        self::assertSame($result->countsBySeverity(), $json['summary']);
    }
}
