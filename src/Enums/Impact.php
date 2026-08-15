<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/**
 * Exploitation impact. Values and weights mirror Threagile
 * `types.RiskExploitationImpact`.
 */
enum Impact: string
{
    case Low      = 'low';
    case Medium   = 'medium';
    case High     = 'high';
    case VeryHigh = 'very-high';

    public function weight(): int
    {
        return match ($this) {
            self::Low      => 1,
            self::Medium   => 2,
            self::High     => 3,
            self::VeryHigh => 4,
        };
    }

    /** Shift up/down the scale, clamped at both ends. Used by scoring modifiers. */
    public function shift(int $steps): self
    {
        $cases = self::cases();
        $index = max(0, min(count($cases) - 1, array_search($this, $cases, true) + $steps));

        return $cases[$index];
    }

    public function label(): string
    {
        return match ($this) {
            self::Low      => 'Low',
            self::Medium   => 'Medium',
            self::High     => 'High',
            self::VeryHigh => 'Very High',
        };
    }
}
