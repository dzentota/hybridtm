<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\Enums\Severity;

/** Knobs for one analysis run. */
final readonly class AnalysisOptions
{
    /**
     * @param list<string> $onlyRules evaluate just these rule ids (empty = all)
     * @param list<string> $skipRules rule ids to skip, e.g. disabled by an org KB
     */
    public function __construct(
        public Severity $minSeverity = Severity::Low,
        public bool $includeSuppressed = false,
        public bool $collectTraces = true,
        public array $onlyRules = [],
        public array $skipRules = [],
    ) {
    }
}
