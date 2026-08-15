<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\Finding;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Severity;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class FindingTest extends TestCase
{
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
        $this->expectException(InvalidArgumentException::class);
        $this->finding()->mergeWith($this->finding(subjectId: 'other-db'));
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
