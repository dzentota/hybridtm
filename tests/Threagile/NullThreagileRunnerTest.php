<?php

declare(strict_types=1);

namespace HybridTM\Tests\Threagile;

use HybridTM\Threagile\NullThreagileRunner;
use HybridTM\Threagile\ThreagileRunException;
use PHPUnit\Framework\TestCase;

final class NullThreagileRunnerTest extends TestCase
{
    private string $tmpDir;
    private string $yamlPath;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_null_runner_' . uniqid('', true);
        mkdir($this->tmpDir, 0o755, true);
        $this->yamlPath = $this->tmpDir . '/model.yaml';
        file_put_contents($this->yamlPath, 'title: Test');
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmpDir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->tmpDir);
    }

    public function testWritesDefaultEmptyRisksJson(): void
    {
        $result = (new NullThreagileRunner())->run($this->yamlPath, $this->tmpDir);

        self::assertTrue($result->succeeded());
        self::assertNotNull($result->risksJsonPath, 'Expected a risks.json path on success.');
        self::assertSame('[]', file_get_contents($result->risksJsonPath));
        self::assertSame(0, $result->exitCode);
        self::assertSame('null-runner', $result->engineVersion);
    }

    public function testWritesCannedRisksJson(): void
    {
        $canned = '[{"id":"unencrypted-asset"}]';
        $result = (new NullThreagileRunner($canned))->run($this->yamlPath, $this->tmpDir);

        self::assertNotNull($result->risksJsonPath, 'Expected a risks.json path on success.');
        self::assertSame($canned, file_get_contents($result->risksJsonPath));
    }

    public function testThrowsWhenOutputDirectoryDoesNotExist(): void
    {
        $this->expectException(ThreagileRunException::class);
        (new NullThreagileRunner())->run($this->yamlPath, $this->tmpDir . '/does-not-exist');
    }
}
