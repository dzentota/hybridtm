<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\DSL\ThreatModel;

/**
 * Pre-computed lookups over a `ThreatModel`, built once before the rule
 * engine runs (§5.2 "Index" phase). Rules that walked the raw model with
 * nested loops to answer "which assets have this trait" or "what flows into
 * this asset" degrade to O(n²) on realistic graphs; every lookup here is
 * O(1) after `build()`.
 *
 * Immutable: rebuild the whole index if the model changes.
 */
final class ModelIndex
{
    /** @var array<string, list<string>> trait => assetIds carrying it */
    private array $traitsIndex = [];

    /** @var array<string, list<IndexedLink>> assetId => links originating from it */
    private array $outgoing = [];

    /** @var array<string, list<IndexedLink>> assetId => links targeting it */
    private array $incoming = [];

    /** @var array<string, string> assetId => id of the trust boundary containing it */
    private array $boundaryOf = [];

    /** @var array<string, list<string>> dataAssetId => assetIds that process or store it */
    private array $dataAssetUsage = [];

    private function __construct()
    {
    }

    public static function build(ThreatModel $model): self
    {
        $index = new self();

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            foreach ($asset->traits as $trait) {
                $index->traitsIndex[$trait][] = $assetId;
            }

            foreach (array_unique([...$asset->dataAssetsProcessed, ...$asset->dataAssetsStored]) as $dataId) {
                $index->dataAssetUsage[$dataId][] = $assetId;
            }

            foreach ($asset->communicationLinks as $link) {
                $indexed = new IndexedLink($assetId, $link);
                $index->outgoing[$assetId][] = $indexed;
                $index->incoming[$link->targetAssetId][] = $indexed;
            }
        }

        foreach ($model->getTrustBoundaries() as $boundaryId => $boundary) {
            foreach ($boundary->technicalAssetsInside as $assetId) {
                $index->boundaryOf[$assetId] = $boundaryId;
            }
        }

        return $index;
    }

    /** @return list<string> */
    public function assetsWithTrait(string $trait): array
    {
        return $this->traitsIndex[$trait] ?? [];
    }

    /** @return list<IndexedLink> */
    public function outgoingLinks(string $assetId): array
    {
        return $this->outgoing[$assetId] ?? [];
    }

    /** @return list<IndexedLink> */
    public function incomingLinks(string $assetId): array
    {
        return $this->incoming[$assetId] ?? [];
    }

    public function boundaryOf(string $assetId): ?string
    {
        return $this->boundaryOf[$assetId] ?? null;
    }

    /** @return list<string> */
    public function assetsUsingDataAsset(string $dataAssetId): array
    {
        return $this->dataAssetUsage[$dataAssetId] ?? [];
    }
}
