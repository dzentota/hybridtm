<?php

declare(strict_types=1);

namespace HybridTM\Compiler;

final class AstResult
{
    /**
     * @param list<DiscoveredDataFlow> $dataFlows
     * @param list<DiscoveredMitigation> $mitigations
     * @param list<DiscoveredProcessesData> $processesData
     * @param list<string> $warnings
     */
    public function __construct(
        public readonly array $dataFlows = [],
        public readonly array $mitigations = [],
        public readonly array $processesData = [],
        public readonly array $warnings = [],
    ) {
    }
}
