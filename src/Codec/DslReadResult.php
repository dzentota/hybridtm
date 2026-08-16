<?php
declare(strict_types=1);
namespace HybridTM\Codec;

use HybridTM\DSL\ThreatModel;

/**
 * Result of `PhpDslReader::read()`. `$canonical === false` means the file
 * contained constructs outside ADR-08's recognizable subset — `$model` is
 * still whatever could be built from the constructs that WERE recognized
 * (per ADR-08: "view and analysis remain available", only round-trip
 * writing is unsafe), and `$nonCanonical` explains what to fix.
 */
final readonly class DslReadResult
{
    /** @param list<NonCanonicalConstruct> $nonCanonical */
    public function __construct(
        public ?ThreatModel $model,
        public array $nonCanonical = [],
    ) {
    }

    public function isCanonical(): bool
    {
        return $this->nonCanonical === [];
    }
}
