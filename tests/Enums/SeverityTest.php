<?php
declare(strict_types=1);
namespace HybridTM\Tests\Enums;

use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Severity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The severity formula must stay bit-identical to Threagile
 * `types.CalculateSeverity()` (product of weights, bucketed at 1/3/8/12).
 * If these expectations ever need changing, the merge logic in the unified
 * risk register becomes meaningless — treat a failure here as a red flag,
 * not as a test to update.
 */
final class SeverityTest extends TestCase
{
    /** @return iterable<string, array{Likelihood, Impact, Severity}> */
    public static function matrix(): iterable
    {
        // Full 4x4 grid, values derived from Threagile's weight product.
        $expected = [
            'unlikely'    => ['low' => Severity::Low,      'medium' => Severity::Medium,   'high' => Severity::Medium, 'very-high' => Severity::Elevated],
            'likely'      => ['low' => Severity::Medium,   'medium' => Severity::Elevated, 'high' => Severity::Elevated, 'very-high' => Severity::Elevated],
            'very-likely' => ['low' => Severity::Medium,   'medium' => Severity::Elevated, 'high' => Severity::High,   'very-high' => Severity::High],
            'frequent'    => ['low' => Severity::Elevated, 'medium' => Severity::Elevated, 'high' => Severity::High,   'very-high' => Severity::Critical],
        ];

        foreach ($expected as $likelihood => $row) {
            foreach ($row as $impact => $severity) {
                yield "{$likelihood} x {$impact}" => [
                    Likelihood::from($likelihood),
                    Impact::from($impact),
                    $severity,
                ];
            }
        }
    }

    #[DataProvider('matrix')]
    public function testCalculateMatchesThreagile(Likelihood $l, Impact $i, Severity $expected): void
    {
        self::assertSame($expected, Severity::calculate($l, $i));
    }

    public function testWeightsMatchThreagile(): void
    {
        self::assertSame([1, 2, 3, 4], array_map(static fn (Likelihood $l): int => $l->weight(), Likelihood::cases()));
        self::assertSame([1, 2, 3, 4], array_map(static fn (Impact $i): int => $i->weight(), Impact::cases()));
    }

    public function testRankIsMonotonic(): void
    {
        $ranks = array_map(static fn (Severity $s): int => $s->rank(), Severity::cases());
        $sorted = $ranks;
        sort($sorted);

        self::assertSame($sorted, $ranks, 'Severity cases must be declared in ascending order of rank.');
        self::assertSame([1, 2, 3, 4, 5], $ranks);
    }

    public function testIsAtLeast(): void
    {
        self::assertTrue(Severity::Critical->isAtLeast(Severity::High));
        self::assertTrue(Severity::High->isAtLeast(Severity::High));
        self::assertFalse(Severity::Medium->isAtLeast(Severity::High));
    }

    public function testMax(): void
    {
        self::assertSame(Severity::High, Severity::max(Severity::Low, Severity::High, Severity::Medium));
        self::assertSame(Severity::Low, Severity::max());
    }
}
