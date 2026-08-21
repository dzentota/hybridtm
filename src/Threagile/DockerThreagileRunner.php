<?php

declare(strict_types=1);

namespace HybridTM\Threagile;

/**
 * Runs Threagile via Docker (§5.5) — isolated network, read-only input
 * mount, a pinned image tag (never `latest`, or results stop being
 * reproducible), and `-generate-risks-json` since Threagile doesn't emit
 * that file by default.
 */
final class DockerThreagileRunner extends AbstractProcessThreagileRunner
{
    public function __construct(private readonly string $dockerBinary = 'docker')
    {
    }

    protected function buildCommand(string $yamlPath, string $outDir, RunOptions $options): array
    {
        $modelDir = dirname((string) realpath($yamlPath));
        $outputDir = (string) realpath($outDir);
        $modelFile = basename($yamlPath);

        return [
            $this->dockerBinary, 'run', '--rm',
            '--network=none',
            '--cpus=' . $options->cpuLimit,
            '--memory=' . $options->memoryLimit,
            '-v', "{$modelDir}:/app/work:ro",
            '-v', "{$outputDir}:/app/output",
            "threagile/threagile:{$options->imageVersion}",
            '-model', "/app/work/{$modelFile}",
            '-output', '/app/output',
            '-generate-risks-json',
            ...($options->verbose ? ['-verbose'] : []),
        ];
    }

    protected function engineVersion(RunOptions $options): string
    {
        return "threagile/threagile:{$options->imageVersion}";
    }
}
