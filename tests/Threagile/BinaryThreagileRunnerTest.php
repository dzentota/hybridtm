<?php

declare(strict_types=1);

namespace HybridTM\Tests\Threagile;

use HybridTM\Threagile\BinaryThreagileRunner;
use HybridTM\Threagile\RunOptions;
use HybridTM\Threagile\ThreagileRunException;
use PHPUnit\Framework\TestCase;

/**
 * No real Threagile binary is available in this environment, so these
 * tests point BinaryThreagileRunner at a small stand-in PHP script that
 * plays the part of "threagile": it parses -model/-output/-generate-
 * risks-json/-verbose like the real CLI does, and its behaviour (exit
 * code, risks.json content, sleep duration) is controlled via env vars.
 * This verifies the runner's own plumbing (command building, timeout
 * enforcement, risks.json detection) without depending on Docker or a
 * real Threagile install.
 */
final class BinaryThreagileRunnerTest extends TestCase
{
    private string $tmpDir;
    private string $yamlPath;
    private string $fakeBinary;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_binary_runner_' . uniqid('', true);
        mkdir($this->tmpDir, 0o755, true);
        $this->yamlPath = $this->tmpDir . '/model.yaml';
        file_put_contents($this->yamlPath, 'title: Test');

        $this->fakeBinary = $this->tmpDir . '/fake-threagile';
        file_put_contents($this->fakeBinary, <<<'PHP'
            #!/usr/bin/env php
            <?php
            $args = $argv;
            $output = null;
            $verbose = false;
            $generateRisksJson = false;
            for ($i = 1; $i < count($args); $i++) {
                if ($args[$i] === '-output') { $output = $args[++$i]; }
                elseif ($args[$i] === '-model') { $i++; }
                elseif ($args[$i] === '-verbose') { $verbose = true; }
                elseif ($args[$i] === '-generate-risks-json') { $generateRisksJson = true; }
            }
            if ($verbose) { fwrite(STDOUT, "verbose output\n"); }
            if (getenv('FAKE_THREAGILE_SLEEP')) { sleep((int) getenv('FAKE_THREAGILE_SLEEP')); }
            if (getenv('FAKE_THREAGILE_FAIL')) { fwrite(STDERR, "simulated failure\n"); exit(1); }
            if ($generateRisksJson && $output !== null && !getenv('FAKE_THREAGILE_NO_RISKS_FILE')) {
                file_put_contents($output . '/risks.json', getenv('FAKE_THREAGILE_RISKS') ?: '[]');
            }
            exit(0);
            PHP);
        chmod($this->fakeBinary, 0o755);
    }

    protected function tearDown(): void
    {
        putenv('FAKE_THREAGILE_SLEEP');
        putenv('FAKE_THREAGILE_FAIL');
        putenv('FAKE_THREAGILE_RISKS');
        putenv('FAKE_THREAGILE_NO_RISKS_FILE');
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

    private function runner(): BinaryThreagileRunner
    {
        return new BinaryThreagileRunner($this->fakeBinary, version: '1.0.0');
    }

    public function testSucceedsAndProducesRisksJson(): void
    {
        putenv('FAKE_THREAGILE_RISKS=[{"id":"unencrypted-asset"}]');
        $result = $this->runner()->run($this->yamlPath, $this->tmpDir);

        self::assertTrue($result->succeeded());
        self::assertSame(0, $result->exitCode);
        self::assertNotNull($result->risksJsonPath, 'Expected a risks.json path on success.');
        self::assertSame('[{"id":"unencrypted-asset"}]', file_get_contents($result->risksJsonPath));
        self::assertSame('1.0.0', $result->engineVersion);
    }

    public function testVerboseFlagIsPassedThrough(): void
    {
        $result = $this->runner()->run($this->yamlPath, $this->tmpDir, new RunOptions(verbose: true));
        self::assertStringContainsString('verbose output', $result->stdout);
    }

    public function testNonZeroExitCodeIsReported(): void
    {
        putenv('FAKE_THREAGILE_FAIL=1');
        $result = $this->runner()->run($this->yamlPath, $this->tmpDir);

        self::assertSame(1, $result->exitCode);
        self::assertFalse($result->succeeded());
        self::assertStringContainsString('simulated failure', $result->stderr);
    }

    public function testMissingRisksJsonMeansNotSucceeded(): void
    {
        // Exit code 0 but no risks.json produced at all (e.g. Threagile ran
        // but the flag requesting JSON output was somehow not honored).
        putenv('FAKE_THREAGILE_NO_RISKS_FILE=1');

        $result = $this->runner()->run($this->yamlPath, $this->tmpDir);

        self::assertSame(0, $result->exitCode);
        self::assertNull($result->risksJsonPath);
        self::assertFalse($result->succeeded());
    }

    public function testThrowsOnTimeout(): void
    {
        putenv('FAKE_THREAGILE_SLEEP=5');
        $this->expectException(ThreagileRunException::class);
        $this->expectExceptionMessageMatches('/timeout/');

        $this->runner()->run($this->yamlPath, $this->tmpDir, new RunOptions(timeoutSeconds: 1));
    }

    public function testThrowsWhenOutputDirectoryDoesNotExist(): void
    {
        $this->expectException(ThreagileRunException::class);
        $this->runner()->run($this->yamlPath, $this->tmpDir . '/nonexistent');
    }

    public function testThrowsWhenModelFileDoesNotExist(): void
    {
        $this->expectException(ThreagileRunException::class);
        $this->runner()->run($this->tmpDir . '/nonexistent.yaml', $this->tmpDir);
    }

    public function testRecordsDuration(): void
    {
        $result = $this->runner()->run($this->yamlPath, $this->tmpDir);
        self::assertGreaterThanOrEqual(0.0, $result->durationMs);
    }
}
