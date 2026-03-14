<?php
declare(strict_types=1);
namespace HybridTM\Compiler;

final class DiscoveredProcessesData
{
    /** @param string[] $dataAssets */
    public function __construct(
        public readonly array $dataAssets,
        public readonly string $context,
    ) {}
}
