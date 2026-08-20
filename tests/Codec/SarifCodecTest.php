<?php

declare(strict_types=1);

namespace HybridTM\Tests\Codec;

use HybridTM\Analysis\AnalysisResult;
use HybridTM\Analysis\AnalysisStats;
use HybridTM\Analysis\CodeLocation;
use HybridTM\Analysis\Finding;
use HybridTM\Analysis\StandardsMapping;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Codec\SarifCodec;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Validation\ValidationReport;
use PHPUnit\Framework\TestCase;

final class SarifCodecTest extends TestCase
{
    private SarifCodec $codec;

    protected function setUp(): void
    {
        $this->codec = new SarifCodec();
    }

    private function analysisResult(Finding ...$findings): AnalysisResult
    {
        return new AnalysisResult(array_values($findings), new ValidationReport(), new AnalysisStats(), 'hash');
    }

    public function testExportsSchemaAndVersion(): void
    {
        $sarif = $this->codec->export($this->analysisResult());

        self::assertSame('2.1.0', $sarif['version']);
        self::assertArrayHasKey('$schema', $sarif);
        self::assertSame('HybridTM', $sarif['runs'][0]['tool']['driver']['name']);
    }

    public function testOneRulePerDistinctThreatId(): void
    {
        $f1 = Finding::create('THREAT-X', 'rule/a', SubjectRef::component('db'), 'X on db', Likelihood::Likely, Impact::Medium);
        $f2 = Finding::create('THREAT-X', 'rule/b', SubjectRef::component('cache'), 'X on cache', Likelihood::Likely, Impact::Medium);
        $f3 = Finding::create('THREAT-Y', 'rule/c', SubjectRef::component('db'), 'Y on db', Likelihood::Likely, Impact::Medium);

        $sarif = $this->codec->export($this->analysisResult($f1, $f2, $f3));

        self::assertCount(2, $sarif['runs'][0]['tool']['driver']['rules']);
        self::assertCount(3, $sarif['runs'][0]['results']);
    }

    public function testSeverityMapsToSarifLevel(): void
    {
        $critical = Finding::create('THREAT-CRIT', 'rule/a', SubjectRef::component('db'), 'Critical', Likelihood::Frequent, Impact::VeryHigh);
        $low = Finding::create('THREAT-LOW', 'rule/b', SubjectRef::component('db'), 'Low', Likelihood::Unlikely, Impact::Low);

        $sarif = $this->codec->export($this->analysisResult($critical, $low));

        $levelFor = static function (array $sarif, string $ruleId): string {
            foreach ($sarif['runs'][0]['results'] as $r) {
                if ($r['ruleId'] === $ruleId) {
                    return $r['level'];
                }
            }
            throw new \RuntimeException('not found');
        };

        self::assertSame('error', $levelFor($sarif, 'THREAT-CRIT'));
        self::assertSame('note', $levelFor($sarif, 'THREAT-LOW'));
    }

    public function testUsesCodeLocationWhenPresent(): void
    {
        $finding = Finding::create(
            'THREAT-X',
            'rule/a',
            SubjectRef::component('db'),
            'X',
            Likelihood::Likely,
            Impact::Medium,
            codeLocation: new CodeLocation('src/Foo.php', 42, 'App\\Foo', 'save'),
        );

        $sarif = $this->codec->export($this->analysisResult($finding));
        $location = $sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation'];

        self::assertSame('src/Foo.php', $location['artifactLocation']['uri']);
        self::assertSame(42, $location['region']['startLine']);
    }

    public function testDefaultsToThreatModelPhpWhenNoCodeLocation(): void
    {
        $finding = Finding::create('THREAT-X', 'rule/a', SubjectRef::component('db'), 'X', Likelihood::Likely, Impact::Medium);

        $sarif = $this->codec->export($this->analysisResult($finding));
        $location = $sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation'];

        self::assertSame('threat-model.php', $location['artifactLocation']['uri']);
        self::assertSame(1, $location['region']['startLine']);
    }

    public function testIncludesCweHelpLinksAndCountermeasures(): void
    {
        $finding = Finding::create(
            'THREAT-X',
            'rule/a',
            SubjectRef::component('db'),
            'X',
            Likelihood::Likely,
            Impact::Medium,
            countermeasureIds: ['CM-ENCRYPT-AT-REST'],
            standards: new StandardsMapping(cwe: [311, 312]),
        );

        $sarif = $this->codec->export($this->analysisResult($finding));
        $rule = $sarif['runs'][0]['tool']['driver']['rules'][0];

        self::assertSame([311, 312], $rule['properties']['cwe']);
        self::assertStringContainsString('cwe.mitre.org/data/definitions/311.html', $rule['help']['markdown']);
        self::assertStringContainsString('CM-ENCRYPT-AT-REST', $rule['help']['markdown']);
    }

    public function testStableFingerprintUsesFindingStableId(): void
    {
        $finding = Finding::create('THREAT-X', 'rule/a', SubjectRef::component('db'), 'X', Likelihood::Likely, Impact::Medium);

        $sarif = $this->codec->export($this->analysisResult($finding));

        self::assertSame($finding->stableId, $sarif['runs'][0]['results'][0]['partialFingerprints']['hybridtmStableId']);
    }
}
