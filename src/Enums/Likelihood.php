<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/**
 * Exploitation likelihood. Values and weights mirror Threagile
 * `types.RiskExploitationLikelihood` so severities stay comparable
 * when findings from both engines are merged.
 */
enum Likelihood: string
{
    case Unlikely   = 'unlikely';
    case Likely     = 'likely';
    case VeryLikely = 'very-likely';
    case Frequent   = 'frequent';

    public function weight(): int
    {
        return match ($this) {
            self::Unlikely   => 1,
            self::Likely     => 2,
            self::VeryLikely => 3,
            self::Frequent   => 4,
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
            self::Unlikely   => 'Unlikely',
            self::Likely     => 'Likely',
            self::VeryLikely => 'Very Likely',
            self::Frequent   => 'Frequent',
        };
    }
}
