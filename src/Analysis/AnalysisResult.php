<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

use HybridTM\Enums\Severity;
use HybridTM\Validation\ValidationReport;

/** Everything one analysis run produced. */
final readonly class AnalysisResult implements \JsonSerializable
{
    /** @param list<Finding> $findings */
    public function __construct(
        public array $findings,
        public ValidationReport $validation,
        public AnalysisStats $stats,
        public string $inputHash,
    ) {
    }

    /** @return list<Finding> */
    public function atLeast(Severity $threshold): array
    {
        return array_values(array_filter(
            $this->findings,
            static fn (Finding $f): bool => $f->severity->isAtLeast($threshold),
        ));
    }

    /** @return array<string, int> severity value => count */
    public function countsBySeverity(): array
    {
        $counts = [];
        foreach (Severity::cases() as $severity) {
            $counts[$severity->value] = 0;
        }
        foreach ($this->findings as $finding) {
            ++$counts[$finding->severity->value];
        }

        return $counts;
    }

    public function highestSeverity(): ?Severity
    {
        if ($this->findings === []) {
            return null;
        }

        return Severity::max(...array_map(static fn (Finding $f): Severity => $f->severity, $this->findings));
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'inputHash'  => $this->inputHash,
            'findings'   => $this->findings,
            'validation' => $this->validation,
            'stats'      => $this->stats,
            'summary'    => $this->countsBySeverity(),
        ];
    }
}
