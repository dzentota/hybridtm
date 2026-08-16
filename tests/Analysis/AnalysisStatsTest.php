<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\AnalysisStats;
use PHPUnit\Framework\TestCase;

final class AnalysisStatsTest extends TestCase
{
    public function testDefaultsAreAllZeroOrEmpty(): void
    {
        $stats = new AnalysisStats();

        self::assertSame(0, $stats->rulesEvaluated);
        self::assertSame(0, $stats->rulesMatched);
        self::assertSame(0.0, $stats->durationMs);
        self::assertSame([], $stats->phaseDurationsMs);
        self::assertSame('', $stats->engineVersion);
        self::assertSame('', $stats->kbVersion);
        self::assertNull($stats->threagileVersion);
    }

    public function testJsonSerializeRoundsDurationsToThreeDecimals(): void
    {
        $stats = new AnalysisStats(
            rulesEvaluated: 10,
            rulesMatched: 3,
            durationMs: 12.34567,
            phaseDurationsMs: ['validate' => 1.23456, 'rules' => 9.87654],
            engineVersion: '0.1.0',
            kbVersion: 'kb-core@1.0.0',
            threagileVersion: '1.0.0',
        );

        $json = $stats->jsonSerialize();

        self::assertSame(10, $json['rulesEvaluated']);
        self::assertSame(3, $json['rulesMatched']);
        self::assertSame(12.346, $json['durationMs']);
        self::assertSame(['validate' => 1.235, 'rules' => 9.877], $json['phaseDurationsMs']);
        self::assertSame('0.1.0', $json['engineVersion']);
        self::assertSame('kb-core@1.0.0', $json['kbVersion']);
        self::assertSame('1.0.0', $json['threagileVersion']);
    }

    public function testThreagileVersionCanBeNullInJson(): void
    {
        $stats = new AnalysisStats();

        self::assertNull($stats->jsonSerialize()['threagileVersion']);
    }
}
