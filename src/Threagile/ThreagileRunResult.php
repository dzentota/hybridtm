<?php

declare(strict_types=1);

namespace HybridTM\Threagile;

/** Outcome of one `ThreagileRunnerInterface::run()` call. */
final readonly class ThreagileRunResult
{
    public function __construct(
        public int $exitCode,
        public string $stdout,
        public string $stderr,
        public ?string $risksJsonPath,
        public string $engineVersion,
        public float $durationMs,
    ) {
    }

    public function succeeded(): bool
    {
        return $this->exitCode === 0 && $this->risksJsonPath !== null && is_file($this->risksJsonPath);
    }
}
