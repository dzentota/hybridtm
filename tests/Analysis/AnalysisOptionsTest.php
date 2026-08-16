<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Enums\Severity;
use PHPUnit\Framework\TestCase;

final class AnalysisOptionsTest extends TestCase
{
    public function testDefaults(): void
    {
        $options = new AnalysisOptions();

        self::assertSame(Severity::Low, $options->minSeverity);
        self::assertFalse($options->includeSuppressed);
        self::assertTrue($options->collectTraces);
        self::assertSame([], $options->onlyRules);
        self::assertSame([], $options->skipRules);
    }

    public function testAllFieldsAreSettable(): void
    {
        $options = new AnalysisOptions(
            minSeverity: Severity::High,
            includeSuppressed: true,
            collectTraces: false,
            onlyRules: ['rule/a'],
            skipRules: ['rule/b'],
        );

        self::assertSame(Severity::High, $options->minSeverity);
        self::assertTrue($options->includeSuppressed);
        self::assertFalse($options->collectTraces);
        self::assertSame(['rule/a'], $options->onlyRules);
        self::assertSame(['rule/b'], $options->skipRules);
    }
}
