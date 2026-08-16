<?php
declare(strict_types=1);
namespace HybridTM\Threagile;

/**
 * Runs a locally-installed `threagile` binary directly (§5.5) — no Docker
 * required, at the cost of the isolation Docker's `--network=none` gives.
 * `-generate-risks-json` is required explicitly: Threagile does not emit
 * `risks.json` unless asked to.
 */
final class BinaryThreagileRunner extends AbstractProcessThreagileRunner
{
    /**
     * @param string $version recorded as the run's engineVersion — the
     *        binary has no reliable self-reported version flag to
     *        introspect, so the caller states what they installed.
     */
    public function __construct(
        private readonly string $binaryPath = 'threagile',
        private readonly string $version = 'local',
    ) {
    }

    protected function buildCommand(string $yamlPath, string $outDir, RunOptions $options): array
    {
        return [
            $this->binaryPath,
            '-model', $yamlPath,
            '-output', $outDir,
            '-generate-risks-json',
            ...($options->verbose ? ['-verbose'] : []),
        ];
    }

    protected function engineVersion(RunOptions $options): string
    {
        return $this->version;
    }
}
