<?php
declare(strict_types=1);
namespace HybridTM\Compiler;

use HybridTM\Enums\MitigationStatus;

final class DiscoveredMitigation
{
    public function __construct(
        public readonly string $cwe,
        public readonly string $description,
        public readonly MitigationStatus $status,
        public readonly string $context,
    ) {}
}
