<?php
declare(strict_types=1);
namespace HybridTM\Threagile;

/**
 * Shared process-invocation plumbing for `DockerThreagileRunner` and
 * `BinaryThreagileRunner`: build a command, run it under a hard timeout via
 * `proc_open` (no `symfony/process` dependency — this library stays
 * framework-agnostic per ADR-09, and this is the one place a process
 * genuinely needs spawning), and report whether `risks.json` actually
 * showed up in `$outDir` afterward.
 */
abstract class AbstractProcessThreagileRunner implements ThreagileRunnerInterface
{
    public function run(string $yamlPath, string $outDir, RunOptions $options = new RunOptions()): ThreagileRunResult
    {
        if (!is_file($yamlPath)) {
            throw new ThreagileRunException("Model YAML not found: {$yamlPath}");
        }
        if (!is_dir($outDir)) {
            // Threagile itself does not create the output directory — the
            // project's own README warns about this explicitly (§5.5).
            throw new ThreagileRunException("Output directory does not exist: {$outDir}");
        }

        $command = $this->buildCommand($yamlPath, $outDir, $options);

        $start = hrtime(true);
        [$exitCode, $stdout, $stderr] = $this->runProcess($command, $options->timeoutSeconds);
        $durationMs = (hrtime(true) - $start) / 1_000_000;

        $risksPath = rtrim($outDir, '/') . '/risks.json';

        return new ThreagileRunResult(
            exitCode: $exitCode,
            stdout: $stdout,
            stderr: $stderr,
            risksJsonPath: is_file($risksPath) ? $risksPath : null,
            engineVersion: $this->engineVersion($options),
            durationMs: $durationMs,
        );
    }

    /** @return list<string> argv, unescaped — escaping happens in runProcess() */
    abstract protected function buildCommand(string $yamlPath, string $outDir, RunOptions $options): array;

    abstract protected function engineVersion(RunOptions $options): string;

    /**
     * @param list<string> $argv
     * @return array{0: int, 1: string, 2: string} exit code, stdout, stderr
     */
    private function runProcess(array $argv, int $timeoutSeconds): array
    {
        $commandLine = implode(' ', array_map('escapeshellarg', $argv));
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];

        $process = proc_open($commandLine, $descriptors, $pipes);
        if (!is_resource($process)) {
            throw new ThreagileRunException("Failed to start process: {$commandLine}");
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout = '';
        $stderr = '';
        $deadline = microtime(true) + $timeoutSeconds;

        while (true) {
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);

            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }

            if (microtime(true) > $deadline) {
                proc_terminate($process, 9);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                throw new ThreagileRunException("Threagile run exceeded the {$timeoutSeconds}s timeout");
            }

            usleep(50_000);
        }

        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        return [$exitCode, $stdout, $stderr];
    }
}
