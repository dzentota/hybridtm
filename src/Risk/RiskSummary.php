<?php

declare(strict_types=1);

namespace HybridTM\Risk;

use HybridTM\Analysis\Finding;
use HybridTM\Enums\Severity;

/**
 * Counts of findings by severity (§5.6). Trend (change since a prior
 * summary) is not implemented here — it needs a stored time series of
 * past summaries, which is a persistence/API-layer concern (E6), not
 * something this in-memory value object can compute on its own from a
 * single analysis run.
 */
final readonly class RiskSummary implements \JsonSerializable
{
    /** @param array<string, int> $countsBySeverity */
    public function __construct(
        public array $countsBySeverity,
        public int $total,
    ) {
    }

    /** @param list<Finding> $findings */
    public static function from(array $findings): self
    {
        $counts = [];
        foreach (Severity::cases() as $severity) {
            $counts[$severity->value] = 0;
        }
        foreach ($findings as $finding) {
            ++$counts[$finding->severity->value];
        }

        return new self($counts, count($findings));
    }

    /** @return array{countsBySeverity: array<string, int>, total: int} */
    public function jsonSerialize(): array
    {
        return ['countsBySeverity' => $this->countsBySeverity, 'total' => $this->total];
    }
}
