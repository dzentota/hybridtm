<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/**
 * Risk severity.
 *
 * `calculate()` reproduces Threagile `types.CalculateSeverity()` exactly:
 * the product of likelihood and impact weights is bucketed as
 * <=1 low, <=3 medium, <=8 elevated, <=12 high, otherwise critical.
 * Keeping the formula identical is what makes merging HybridTM and
 * Threagile findings into one register meaningful.
 */
enum Severity: string
{
    case Low      = 'low';
    case Medium   = 'medium';
    case Elevated = 'elevated';
    case High     = 'high';
    case Critical = 'critical';

    public static function calculate(Likelihood $likelihood, Impact $impact): self
    {
        $product = $likelihood->weight() * $impact->weight();

        return match (true) {
            $product <= 1  => self::Low,
            $product <= 3  => self::Medium,
            $product <= 8  => self::Elevated,
            $product <= 12 => self::High,
            default        => self::Critical,
        };
    }

    /** Ordinal rank, 1 (low) .. 5 (critical). Use for sorting and thresholds. */
    public function rank(): int
    {
        return match ($this) {
            self::Low      => 1,
            self::Medium   => 2,
            self::Elevated => 3,
            self::High     => 4,
            self::Critical => 5,
        };
    }

    public function isAtLeast(self $threshold): bool
    {
        return $this->rank() >= $threshold->rank();
    }

    public static function max(self ...$severities): self
    {
        $max = self::Low;
        foreach ($severities as $severity) {
            if ($severity->rank() > $max->rank()) {
                $max = $severity;
            }
        }

        return $max;
    }
}
