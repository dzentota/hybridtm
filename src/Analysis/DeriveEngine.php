<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Confidentiality;

/**
 * Derive phase (§5.2 phase 3, §4.2): computes trait names that follow from
 * the model's topology rather than being declared by a KB component.
 *
 * Implements 5 of the 7 traits from the plan's derived-trait table.
 * `crosses_trust_boundary` is deliberately not here — it is a property of a
 * *flow*, not an asset, and `FlowSubject::crossesTrustBoundary()` computes
 * it directly from `ModelIndex` without needing a precomputed set.
 * `single_point_of_failure`'s "degree > 2" threshold is taken literally
 * from §4.2 and only counts *incoming* links (in-degree), since that is
 * what "too many dependents for one non-redundant asset" means.
 */
final class DeriveEngine
{
    public function derive(ThreatModel $model, ModelIndex $index): DerivedTraits
    {
        $traits = new DerivedTraits();

        $this->deriveInternetReachable($model, $index, $traits);

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            if ($this->storesPii($model, $asset)) {
                $traits->add($assetId, 'stores_pii');
            }
            if ($this->handlesStrictlyConfidential($model, $asset)) {
                $traits->add($assetId, 'handles_strictly_confidential');
            }
            if ($asset->redundant === false && count($index->incomingLinks($assetId)) > 2) {
                $traits->add($assetId, 'single_point_of_failure');
            }
            if ($this->isDirectlyExposedDatastore($model, $index, $assetId, $asset)) {
                $traits->add($assetId, 'directly_exposed_datastore');
            }
            if ($this->isBehindWaf($model, $index, $assetId)) {
                $traits->add($assetId, 'behind_waf');
            }
        }

        return $traits;
    }

    private function deriveInternetReachable(ThreatModel $model, ModelIndex $index, DerivedTraits $traits): void
    {
        $queue = [];
        $visited = [];
        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            if ($asset->internet) {
                $queue[] = $assetId;
                $visited[$assetId] = true;
            }
        }

        while ($queue !== []) {
            $current = array_shift($queue);
            $traits->add($current, 'internet_reachable');

            foreach ($index->outgoingLinks($current) as $link) {
                $targetId = $link->targetAssetId;
                if (!isset($visited[$targetId])) {
                    $visited[$targetId] = true;
                    $queue[] = $targetId;
                }
            }
        }
    }

    private function storesPii(ThreatModel $model, \HybridTM\DSL\TechnicalAsset $asset): bool
    {
        foreach ($asset->dataAssetsStored as $dataId) {
            $dataAsset = $model->getDataAsset($dataId);
            if ($dataAsset !== null && in_array('pii', $dataAsset->tags, true)) {
                return true;
            }
        }
        return false;
    }

    private function handlesStrictlyConfidential(ThreatModel $model, \HybridTM\DSL\TechnicalAsset $asset): bool
    {
        foreach ([...$asset->dataAssetsProcessed, ...$asset->dataAssetsStored] as $dataId) {
            if ($model->getDataAsset($dataId)?->confidentiality === Confidentiality::StrictlyConfidential) {
                return true;
            }
        }
        return false;
    }

    private function isDirectlyExposedDatastore(ThreatModel $model, ModelIndex $index, string $assetId, \HybridTM\DSL\TechnicalAsset $asset): bool
    {
        if (!$asset->hasTrait('datastore')) {
            return false;
        }

        foreach ($index->incomingLinks($assetId) as $link) {
            if ($model->getTechnicalAsset($link->sourceAssetId)?->internet === true) {
                return true;
            }
        }
        return false;
    }

    /** BFS backwards along incoming links, looking for an ancestor declaring the 'waf' trait. */
    private function isBehindWaf(ThreatModel $model, ModelIndex $index, string $assetId): bool
    {
        $queue = array_map(
            static fn ($link): string => $link->sourceAssetId,
            $index->incomingLinks($assetId),
        );
        $visited = array_fill_keys($queue, true);

        while ($queue !== []) {
            $current = array_shift($queue);
            if ($model->getTechnicalAsset($current)?->hasTrait('waf') === true) {
                return true;
            }

            foreach ($index->incomingLinks($current) as $link) {
                $sourceId = $link->sourceAssetId;
                if (!isset($visited[$sourceId])) {
                    $visited[$sourceId] = true;
                    $queue[] = $sourceId;
                }
            }
        }

        return false;
    }
}
