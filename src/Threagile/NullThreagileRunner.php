<?php
declare(strict_types=1);
namespace HybridTM\Threagile;

/**
 * For tests and offline environments (§5.5): never shells out, just writes
 * a canned `risks.json` (default: an empty risk list) to `$outDir` and
 * reports success. Inject a specific JSON string to simulate a particular
 * Threagile response without needing Docker or the binary installed.
 */
final class NullThreagileRunner implements ThreagileRunnerInterface
{
    public function __construct(private readonly string $cannedRisksJson = '[]')
    {
    }

    public function run(string $yamlPath, string $outDir, RunOptions $options = new RunOptions()): ThreagileRunResult
    {
        if (!is_dir($outDir)) {
            throw new ThreagileRunException("Output directory does not exist: {$outDir}");
        }

        $path = rtrim($outDir, '/') . '/risks.json';
        file_put_contents($path, $this->cannedRisksJson);

        return new ThreagileRunResult(
            exitCode: 0,
            stdout: '',
            stderr: '',
            risksJsonPath: $path,
            engineVersion: 'null-runner',
            durationMs: 0.0,
        );
    }
}
