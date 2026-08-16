<?php
declare(strict_types=1);
namespace HybridTM\Threagile;

/**
 * Runs Threagile's "deep analysis" pass against a compiled YAML model
 * (§5.5, ADR-01) — asynchronous and only invoked on demand ("Deep
 * analysis" button, or CI), unlike the synchronous `RuleEngine` that runs
 * on every editor keystroke.
 */
interface ThreagileRunnerInterface
{
    /**
     * @throws ThreagileRunException if `$outDir` doesn't exist — Threagile
     *         does not create it, the project's own README warns about this
     */
    public function run(string $yamlPath, string $outDir, RunOptions $options = new RunOptions()): ThreagileRunResult;
}
