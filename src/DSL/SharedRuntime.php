<?php

declare(strict_types=1);

namespace HybridTM\DSL;

/**
 * A runtime (host, cluster, VM) that co-locates several technical assets.
 * Required for Threagile's `mixed-targets-on-shared-runtime` rule to fire
 * at all (§3.1).
 */
class SharedRuntime
{
    public string $description = '';
    /** @var string[] */
    public array $tags = [];
    /** @var string[] IDs of TechnicalAssets running on this runtime */
    public array $technicalAssetsRunning = [];

    public function __construct(
        public readonly string $id,
        public string $name = '',
    ) {
        if ($this->name === '') {
            $this->name = $this->id;
        }
    }

    public function addAssets(string ...$assetIds): static
    {
        foreach ($assetIds as $assetId) {
            if (!in_array($assetId, $this->technicalAssetsRunning, true)) {
                $this->technicalAssetsRunning[] = $assetId;
            }
        }
        return $this;
    }
}
