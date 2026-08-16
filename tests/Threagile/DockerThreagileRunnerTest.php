<?php
declare(strict_types=1);
namespace HybridTM\Tests\Threagile;

use HybridTM\Threagile\DockerThreagileRunner;
use HybridTM\Threagile\RunOptions;
use PHPUnit\Framework\TestCase;

/**
 * Docker is genuinely available in this environment, but it's the user's
 * real daemon running their own long-lived containers — actually invoking
 * `docker run` here (which would pull threagile/threagile and use real
 * resources) is a side effect on shared state this test suite has no
 * business causing. Instead this exercises buildCommand() directly via
 * reflection: the part of DockerThreagileRunner that's actually its own
 * logic, as opposed to the process-invocation plumbing already covered by
 * BinaryThreagileRunnerTest against a harmless stand-in script.
 */
final class DockerThreagileRunnerTest extends TestCase
{
    private string $tmpDir;
    private string $yamlPath;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_docker_runner_' . uniqid('', true);
        mkdir($this->tmpDir, 0755, true);
        $this->yamlPath = $this->tmpDir . '/model.yaml';
        file_put_contents($this->yamlPath, 'title: Test');
    }

    protected function tearDown(): void
    {
        unlink($this->yamlPath);
        rmdir($this->tmpDir);
    }

    /** @return list<string> */
    private function buildCommand(DockerThreagileRunner $runner, RunOptions $options): array
    {
        $method = new \ReflectionMethod(DockerThreagileRunner::class, 'buildCommand');
        return $method->invoke($runner, $this->yamlPath, $this->tmpDir, $options);
    }

    public function testPinsTheImageVersion(): void
    {
        $command = $this->buildCommand(new DockerThreagileRunner(), new RunOptions(imageVersion: '1.2.3'));
        self::assertContains('threagile/threagile:1.2.3', $command);
        self::assertNotContains('threagile/threagile:latest', $command);
    }

    public function testRunsWithIsolatedNetwork(): void
    {
        $command = $this->buildCommand(new DockerThreagileRunner(), new RunOptions());
        self::assertContains('--network=none', $command);
    }

    public function testMountsInputReadOnlyAndOutputWritable(): void
    {
        $command = $this->buildCommand(new DockerThreagileRunner(), new RunOptions());
        $joined = implode(' ', $command);

        self::assertMatchesRegularExpression('#-v .*:/app/work:ro#', $joined);
        self::assertMatchesRegularExpression('#-v .*:/app/output(?!:ro)#', $joined);
    }

    public function testAppliesCpuAndMemoryLimits(): void
    {
        $command = $this->buildCommand(new DockerThreagileRunner(), new RunOptions(cpuLimit: '2', memoryLimit: '512m'));
        self::assertContains('--cpus=2', $command);
        self::assertContains('--memory=512m', $command);
    }

    public function testRequestsRisksJsonGeneration(): void
    {
        $command = $this->buildCommand(new DockerThreagileRunner(), new RunOptions());
        self::assertContains('-generate-risks-json', $command);
    }

    public function testVerboseFlagOnlyPresentWhenRequested(): void
    {
        $quiet = $this->buildCommand(new DockerThreagileRunner(), new RunOptions(verbose: false));
        self::assertNotContains('-verbose', $quiet);

        $verbose = $this->buildCommand(new DockerThreagileRunner(), new RunOptions(verbose: true));
        self::assertContains('-verbose', $verbose);
    }

    public function testUsesConfiguredDockerBinary(): void
    {
        $command = $this->buildCommand(new DockerThreagileRunner('/usr/local/bin/docker'), new RunOptions());
        self::assertSame('/usr/local/bin/docker', $command[0]);
    }

    public function testEngineVersionReflectsPinnedImage(): void
    {
        $runner = new DockerThreagileRunner();
        $method = new \ReflectionMethod(DockerThreagileRunner::class, 'engineVersion');
        self::assertSame('threagile/threagile:1.0.0', $method->invoke($runner, new RunOptions(imageVersion: '1.0.0')));
    }
}
