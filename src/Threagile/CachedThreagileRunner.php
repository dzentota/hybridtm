<?php
declare(strict_types=1);
namespace HybridTM\Threagile;

/**
 * Caches Threagile results by a hash of the YAML input (§5.5, T-5.5): a
 * repeat "deep analysis" on an unchanged model returns instantly instead
 * of paying Docker/Threagile's multi-second cost again. Decorates any
 * `ThreagileRunnerInterface` — including another cached one, though that
 * would just be pointless, not harmful.
 *
 * The cache key includes `$options->imageVersion`: a different pinned
 * image version is a different tool, and must not return a stale result
 * from before an upgrade.
 */
final class CachedThreagileRunner implements ThreagileRunnerInterface
{
    public function __construct(
        private readonly ThreagileRunnerInterface $inner,
        private readonly string $cacheDir,
    ) {
    }

    public function run(string $yamlPath, string $outDir, RunOptions $options = new RunOptions()): ThreagileRunResult
    {
        if (!is_file($yamlPath)) {
            throw new ThreagileRunException("Model YAML not found: {$yamlPath}");
        }
        if (!is_dir($outDir)) {
            throw new ThreagileRunException("Output directory does not exist: {$outDir}");
        }
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }

        $cacheFile = $this->cacheFileFor($yamlPath, $options);

        if (is_file($cacheFile)) {
            $cached = $this->readCache($cacheFile);
            if ($cached !== null) {
                return $this->replayFromCache($cached, $outDir);
            }
        }

        $result = $this->inner->run($yamlPath, $outDir, $options);
        if ($result->succeeded()) {
            $this->writeCache($cacheFile, $result);
        }

        return $result;
    }

    private function cacheFileFor(string $yamlPath, RunOptions $options): string
    {
        $hash = hash('sha256', (string) file_get_contents($yamlPath) . '|' . $options->imageVersion);
        return rtrim($this->cacheDir, '/') . "/{$hash}.json";
    }

    /** @return array{exitCode: int, stdout: string, stderr: string, risksJson: string, engineVersion: string}|null */
    private function readCache(string $cacheFile): ?array
    {
        $contents = file_get_contents($cacheFile);
        $data = $contents !== false ? json_decode($contents, true) : null;
        return is_array($data) ? $data : null;
    }

    /** @param array{exitCode: int, stdout: string, stderr: string, risksJson: string, engineVersion: string} $cached */
    private function replayFromCache(array $cached, string $outDir): ThreagileRunResult
    {
        $risksPath = rtrim($outDir, '/') . '/risks.json';
        file_put_contents($risksPath, $cached['risksJson']);

        return new ThreagileRunResult(
            exitCode: $cached['exitCode'],
            stdout: $cached['stdout'],
            stderr: $cached['stderr'],
            risksJsonPath: $risksPath,
            engineVersion: $cached['engineVersion'],
            durationMs: 0.0,
        );
    }

    private function writeCache(string $cacheFile, ThreagileRunResult $result): void
    {
        $risksJson = (string) file_get_contents((string) $result->risksJsonPath);
        file_put_contents($cacheFile, json_encode([
            'exitCode' => $result->exitCode,
            'stdout' => $result->stdout,
            'stderr' => $result->stderr,
            'risksJson' => $risksJson,
            'engineVersion' => $result->engineVersion,
        ], JSON_THROW_ON_ERROR));
    }
}
