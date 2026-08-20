<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

/** Timing and provenance of one analysis run. Recorded so results are reproducible. */
final readonly class AnalysisStats implements \JsonSerializable
{
    /** @param array<string, float> $phaseDurationsMs keyed by phase name */
    public function __construct(
        public int $rulesEvaluated = 0,
        public int $rulesMatched = 0,
        public float $durationMs = 0.0,
        public array $phaseDurationsMs = [],
        public string $engineVersion = '',
        public string $kbVersion = '',
        public ?string $threagileVersion = null,
    ) {
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'rulesEvaluated' => $this->rulesEvaluated,
            'rulesMatched' => $this->rulesMatched,
            'durationMs' => round($this->durationMs, 3),
            'phaseDurationsMs' => array_map(static fn (float $v): float => round($v, 3), $this->phaseDurationsMs),
            'engineVersion' => $this->engineVersion,
            'kbVersion' => $this->kbVersion,
            'threagileVersion' => $this->threagileVersion,
        ];
    }
}
