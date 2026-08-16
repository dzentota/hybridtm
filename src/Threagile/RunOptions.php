<?php
declare(strict_types=1);
namespace HybridTM\Threagile;

/**
 * Knobs for one Threagile run (§5.5). `$imageVersion` is deliberately
 * never a mutable tag like `latest` — it gets recorded into
 * `AnalysisStats`/`ThreagileRunResult` so results stay reproducible; an
 * unpinned image would mean the same YAML can produce different findings
 * on different days with no way to tell why.
 */
final readonly class RunOptions
{
    public function __construct(
        public string $imageVersion = '1.0.0',
        public int $timeoutSeconds = 120,
        public string $cpuLimit = '1',
        public string $memoryLimit = '1g',
        public bool $verbose = false,
    ) {
    }
}
