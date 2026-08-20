<?php

declare(strict_types=1);

namespace HybridTM\Tests\Threagile;

use HybridTM\Threagile\CachedThreagileRunner;
use HybridTM\Threagile\RunOptions;
use HybridTM\Threagile\ThreagileRunnerInterface;
use HybridTM\Threagile\ThreagileRunResult;
use PHPUnit\Framework\TestCase;

final class CachedThreagileRunnerTest extends TestCase
{
    private string $tmpDir;
    private string $yamlPath;
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_cached_runner_' . uniqid('', true);
        mkdir($this->tmpDir, 0o755, true);
        $this->yamlPath = $this->tmpDir . '/model.yaml';
        file_put_contents($this->yamlPath, 'title: Test');
        $this->cacheDir = $this->tmpDir . '/cache';
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
    }

    private function removeDir(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        foreach (scandir($path) as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $full = $path . '/' . $entry;
            is_dir($full) ? $this->removeDir($full) : unlink($full);
        }
        rmdir($path);
    }

    private function counting(string $risksJson = '[{"id":"x"}]'): CountingFakeRunner
    {
        return new CountingFakeRunner($risksJson);
    }

    public function testFirstRunInvokesInnerRunner(): void
    {
        $inner = $this->counting();
        $result = (new CachedThreagileRunner($inner, $this->cacheDir))->run($this->yamlPath, $this->tmpDir);

        self::assertSame(1, $inner->callCount);
        self::assertTrue($result->succeeded());
        self::assertNotNull($result->risksJsonPath, 'Expected a risks.json path on success.');
        self::assertSame('[{"id":"x"}]', file_get_contents($result->risksJsonPath));
    }

    public function testSecondRunOnUnchangedModelHitsCache(): void
    {
        $inner = $this->counting();
        $cached = new CachedThreagileRunner($inner, $this->cacheDir);

        $cached->run($this->yamlPath, $this->tmpDir);
        $result = $cached->run($this->yamlPath, $this->tmpDir);

        self::assertSame(1, $inner->callCount, 'the second call must not invoke the inner runner again');
        self::assertTrue($result->succeeded());
        self::assertNotNull($result->risksJsonPath, 'Expected a risks.json path on success.');
        self::assertSame('[{"id":"x"}]', file_get_contents($result->risksJsonPath));
    }

    public function testCacheHitIsFast(): void
    {
        $cached = new CachedThreagileRunner($this->counting(), $this->cacheDir);
        $cached->run($this->yamlPath, $this->tmpDir);

        $start = hrtime(true);
        $cached->run($this->yamlPath, $this->tmpDir);
        $elapsedMs = (hrtime(true) - $start) / 1_000_000;

        self::assertLessThan(50.0, $elapsedMs);
    }

    public function testChangedModelInvalidatesCache(): void
    {
        $inner = $this->counting();
        $cached = new CachedThreagileRunner($inner, $this->cacheDir);

        $cached->run($this->yamlPath, $this->tmpDir);
        file_put_contents($this->yamlPath, 'title: Changed');
        $cached->run($this->yamlPath, $this->tmpDir);

        self::assertSame(2, $inner->callCount);
    }

    public function testDifferentImageVersionInvalidatesCache(): void
    {
        $inner = $this->counting();
        $cached = new CachedThreagileRunner($inner, $this->cacheDir);

        $cached->run($this->yamlPath, $this->tmpDir, new RunOptions(imageVersion: '1.0.0'));
        $cached->run($this->yamlPath, $this->tmpDir, new RunOptions(imageVersion: '1.1.0'));

        self::assertSame(2, $inner->callCount);
    }

    public function testCreatesCacheDirectoryIfMissing(): void
    {
        self::assertDirectoryDoesNotExist($this->cacheDir);
        (new CachedThreagileRunner($this->counting(), $this->cacheDir))->run($this->yamlPath, $this->tmpDir);
        self::assertDirectoryExists($this->cacheDir);
    }

    public function testFailedRunIsNotCached(): void
    {
        $inner = new CountingFakeRunner('[]', succeeds: false);
        $cached = new CachedThreagileRunner($inner, $this->cacheDir);

        $cached->run($this->yamlPath, $this->tmpDir);
        $cached->run($this->yamlPath, $this->tmpDir);

        self::assertSame(2, $inner->callCount, 'a failed run must not be cached');
    }
}

/** Minimal spy: counts calls, delegates to NullThreagileRunner-style behavior. */
final class CountingFakeRunner implements ThreagileRunnerInterface
{
    public int $callCount = 0;

    public function __construct(
        private readonly string $risksJson,
        private readonly bool $succeeds = true,
    ) {
    }

    public function run(string $yamlPath, string $outDir, RunOptions $options = new RunOptions()): ThreagileRunResult
    {
        $this->callCount++;

        if (!$this->succeeds) {
            return new ThreagileRunResult(1, '', 'simulated failure', null, 'fake', 1.0);
        }

        $path = rtrim($outDir, '/') . '/risks.json';
        file_put_contents($path, $this->risksJson);

        return new ThreagileRunResult(0, '', '', $path, 'fake', 1.0);
    }
}
