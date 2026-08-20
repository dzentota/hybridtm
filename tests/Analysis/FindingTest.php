<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\Finding;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Severity;
use PHPUnit\Framework\TestCase;

final class FindingTest extends TestCase
{
    /** @param list<string> $evidence */
    private function finding(
        string $rule = 'storage/unencrypted-at-rest',
        string $threat = 'THREAT-DATA-AT-REST-UNENCRYPTED',
        string $subjectId = 'user-db',
        Likelihood $likelihood = Likelihood::Likely,
        Impact $impact = Impact::Medium,
        FindingSource $source = FindingSource::HybridTM,
        string $title = 'Unencrypted data at rest',
        array $evidence = ['user-db stores customer-pii without encryption'],
    ): Finding {
        return Finding::create(
            threatId: $threat,
            ruleId: $rule,
            subject: SubjectRef::component($subjectId),
            title: $title,
            likelihood: $likelihood,
            impact: $impact,
            source: $source,
            evidence: $evidence,
        );
    }

    public function testStableIdIsDeterministic(): void
    {
        self::assertSame($this->finding()->stableId, $this->finding()->stableId);
    }

    public function testStableIdIgnoresDisplayNameAndEvidence(): void
    {
        // Renaming a component or rewording the evidence must not orphan an
        // existing risk decision (ADR-11, ADR-12).
        self::assertSame(
            $this->finding(title: 'Unencrypted data at rest', evidence: ['a'])->stableId,
            $this->finding(title: 'Совершенно другой заголовок', evidence: ['b', 'c'])->stableId,
        );
    }

    public function testStableIdChangesWithRuleThreatOrSubject(): void
    {
        $base = $this->finding()->stableId;

        self::assertNotSame($base, $this->finding(rule: 'storage/other')->stableId);
        self::assertNotSame($base, $this->finding(threat: 'THREAT-OTHER')->stableId);
        self::assertNotSame($base, $this->finding(subjectId: 'other-db')->stableId);
    }

    public function testStableIdFormat(): void
    {
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $this->finding()->stableId);
    }

    public function testSeverityIsDerivedNotSupplied(): void
    {
        self::assertSame(
            Severity::Elevated,
            $this->finding(likelihood: Likelihood::VeryLikely, impact: Impact::Medium)->severity,
        );
    }

    public function testMergeKeepsHigherSeverityAndUnionsEvidence(): void
    {
        $mine = $this->finding(likelihood: Likelihood::Likely, impact: Impact::Medium, evidence: ['from hybridtm']);
        $theirs = $this->finding(
            likelihood: Likelihood::Frequent,
            impact: Impact::VeryHigh,
            source: FindingSource::Threagile,
            evidence: ['from threagile'],
        );

        $merged = $mine->mergeWith($theirs);

        self::assertSame(Severity::Critical, $merged->severity);
        self::assertSame(FindingSource::HybridTM, $merged->source, 'Primary source is preserved.');
        self::assertSame([FindingSource::Threagile], $merged->corroboratedBy);
        self::assertSame(['from hybridtm', 'from threagile'], $merged->evidence);
        self::assertSame($mine->stableId, $merged->stableId);
    }

    public function testMergeRefusesDifferentFindings(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->finding()->mergeWith($this->finding(subjectId: 'other-db'));
    }

    public function testMergeKeepsThisOnEqualSeverityRatherThanSwitchingToOther(): void
    {
        $mine = $this->finding(likelihood: Likelihood::Likely, impact: Impact::Medium, evidence: ['mine']);
        $theirs = $this->finding(likelihood: Likelihood::Likely, impact: Impact::Medium, source: FindingSource::Threagile, evidence: ['theirs']);

        $merged = $mine->mergeWith($theirs);

        // Equal severity must not flip the "winner" to $other — only a
        // strictly higher one should. This distinguishes `>` from `>=` in
        // the tie-break, which otherwise looks identical from the outside
        // since both severities are Elevated either way.
        self::assertSame($mine->likelihood, $merged->likelihood);
        self::assertSame($mine->impact, $merged->impact);
    }

    public function testMergeDoesNotDuplicateASourceThatMatchesThisFindingsSource(): void
    {
        $mine = $this->finding(source: FindingSource::HybridTM);
        $theirs = $this->finding(source: FindingSource::HybridTM);

        $merged = $mine->mergeWith($theirs);

        // $other->source === $this->source here, so the accumulation
        // condition's second operand is false — with a correct `&&` this
        // means corroboratedBy stays empty; a `||` mutant would add it
        // anyway, producing a spurious duplicate corroborating source.
        self::assertSame([], $merged->corroboratedBy);
    }

    public function testWithSeverityRecomputes(): void
    {
        $rescored = $this->finding()->withSeverity(Likelihood::Frequent, Impact::VeryHigh);

        self::assertSame(Severity::Critical, $rescored->severity);
        self::assertSame($this->finding()->stableId, $rescored->stableId);
    }

    public function testJsonShape(): void
    {
        $json = json_decode((string) json_encode($this->finding()), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('component:user-db', $json['subject']);
        self::assertSame('hybridtm', $json['source']);
        self::assertSame('elevated', $json['severity'], 'likely x medium = weight 4 => elevated');
        self::assertArrayHasKey('stableId', $json);
    }
}
