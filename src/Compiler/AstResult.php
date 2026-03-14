<?php
declare(strict_types=1);
namespace HybridTM\Compiler;

final class AstResult
{
    /** @param DiscoveredDataFlow[] $dataFlows */
    /** @param DiscoveredMitigation[] $mitigations */
    /** @param DiscoveredProcessesData[] $processesData */
    /** @param string[] $warnings */
    public function __construct(
        public readonly array $dataFlows = [],
        public readonly array $mitigations = [],
        public readonly array $processesData = [],
        public readonly array $warnings = [],
    ) {}
}
