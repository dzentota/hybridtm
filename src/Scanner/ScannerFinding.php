<?php

declare(strict_types=1);

namespace HybridTM\Scanner;

/**
 * One normalized result from a third-party scanner (T-10.8) — a single
 * rule/check evaluated against a single resource, reduced to whether it
 * passed. `passed = true` is the signal a countermeasure has been
 * verified in the real environment, not just declared in the model.
 */
final readonly class ScannerFinding
{
    public function __construct(
        public string $tool,
        public string $ruleId,
        public bool $passed,
        public string $resource,
    ) {
    }
}
