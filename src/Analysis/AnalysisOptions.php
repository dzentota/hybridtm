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
     * @param list<\HybridTM\Compiler\DiscoveredAbuserStoryRef> $abuserStoryRefs
     */
    public function __construct(
        public Severity $minSeverity = Severity::Low,
        public bool $includeSuppressed = false,
        public bool $collectTraces = true,
        public array $onlyRules = [],
        public array $skipRules = [],
        public ?MitigationIndex $mitigations = null,
        public array $abuserStoryRefs = [],
        public bool $checkStories = false,
        public bool $failOnUncoveredStories = false,
    ) {
    }
}
