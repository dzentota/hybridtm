<?php

declare(strict_types=1);

namespace HybridTM\Tests\Threagile;

use HybridTM\Analysis\Finding;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Severity;
use HybridTM\Threagile\ThreagileMerger;
use PHPUnit\Framework\TestCase;

final class ThreagileMergerTest extends TestCase
{
    private ThreagileMerger $merger;

    protected function setUp(): void
    {
        $this->merger = new ThreagileMerger();
    }

    private function ourFinding(
        string $threatId = 'THREAT-DATA-AT-REST-UNENCRYPTED',
        string $ruleId = 'storage/unencrypted-at-rest',
        string $subjectId = 'db',
        Likelihood $likelihood = Likelihood::Likely,
        Impact $impact = Impact::Medium,
    ): Finding {
        return Finding::create(
            threatId: $threatId,
            ruleId: $ruleId,
            subject: SubjectRef::component($subjectId),
            title: 'Unencrypted data at rest',
            likelihood: $likelihood,
            impact: $impact,
        );
    }

    private function threagileFinding(
        string $category = 'unencrypted-asset',
        string $subjectId = 'db',
        Likelihood $likelihood = Likelihood::Likely,
        Impact $impact = Impact::Medium,
    ): Finding {
        return Finding::create(
            threatId: "THREAGILE-{$category}",
            ruleId: $category,
            subject: SubjectRef::component($subjectId),
            title: 'Unencrypted Asset',
            likelihood: $likelihood,
            impact: $impact,
            source: FindingSource::Threagile,
            evidence: ['synthetic-id-here'],
        );
    }

    public function testMergesMatchingFindingFromBothEngines(): void
    {
        $ours = $this->ourFinding();
        $result = $this->merger->merge([$ours], [$this->threagileFinding()]);

        self::assertCount(1, $result, 'agreement between engines collapses to one finding');
        self::assertSame($ours->stableId, $result[0]->stableId, 'merged finding keeps our own stableId (ADR-12)');
        self::assertSame([FindingSource::Threagile], $result[0]->corroboratedBy);
    }

    public function testMergedFindingTakesMaxSeverity(): void
    {
        $ours = $this->ourFinding(likelihood: Likelihood::Likely, impact: Impact::Medium);
        $theirs = $this->threagileFinding(likelihood: Likelihood::Frequent, impact: Impact::VeryHigh);

        $result = $this->merger->merge([$ours], [$theirs]);
        self::assertSame(Severity::Critical, $result[0]->severity);
    }

    public function testMergedFindingUnionsEvidence(): void
    {
        $result = $this->merger->merge([$this->ourFinding()], [$this->threagileFinding()]);
        self::assertContains('synthetic-id-here', $result[0]->evidence);
    }

    public function testMergeCategoryWithNoMatchingOwnFindingIsAddedStandalone(): void
    {
        // No HybridTM finding for 'app', only Threagile found something there.
        $result = $this->merger->merge([], [$this->threagileFinding(subjectId: 'app')]);

        self::assertCount(1, $result);
        self::assertSame('THREAT-DATA-AT-REST-UNENCRYPTED', $result[0]->threatId, 'still uses the mapped HybridTM threat id');
        self::assertSame(FindingSource::Threagile, $result[0]->source);
        self::assertSame('component:app', (string) $result[0]->subject);
    }

    public function testDifferentSubjectsDoNotMerge(): void
    {
        $ours = $this->ourFinding(subjectId: 'db');
        $theirs = $this->threagileFinding(subjectId: 'cache');

        $result = $this->merger->merge([$ours], [$theirs]);
        self::assertCount(2, $result);
    }

    public function testThreagileOnlyStrategyKeepsFindingAsIs(): void
    {
        $threagileOnly = $this->threagileFinding(category: 'missing-identity-store');
        $result = $this->merger->merge([], [$threagileOnly]);

        self::assertCount(1, $result);
        self::assertSame('THREAGILE-missing-identity-store', $result[0]->threatId);
        self::assertSame(FindingSource::Threagile, $result[0]->source);
    }

    public function testValidationOnlyStrategyDropsTheFinding(): void
    {
        $validationOnly = $this->threagileFinding(category: 'incomplete-model');
        $result = $this->merger->merge([$this->ourFinding()], [$validationOnly]);

        self::assertCount(1, $result, 'only our own finding remains; the validation-only one is dropped');
        self::assertSame('THREAT-DATA-AT-REST-UNENCRYPTED', $result[0]->threatId);
    }

    public function testUnknownCategoryDefaultsToKeptAsIs(): void
    {
        $unknown = $this->threagileFinding(category: 'some-brand-new-threagile-rule');
        $result = $this->merger->merge([], [$unknown]);

        self::assertCount(1, $result);
        self::assertSame(FindingSource::Threagile, $result[0]->source);
    }

    public function testOurOwnUnrelatedFindingsSurviveUntouched(): void
    {
        $unrelated = $this->ourFinding(threatId: 'THREAT-XSS', ruleId: 'web/xss', subjectId: 'web');
        $result = $this->merger->merge([$unrelated], [$this->threagileFinding(subjectId: 'db')]);

        self::assertCount(2, $result);
    }

    public function testEmptyInputsProduceEmptyOutput(): void
    {
        self::assertSame([], $this->merger->merge([], []));
    }
}
