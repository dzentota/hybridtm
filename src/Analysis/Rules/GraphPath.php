<?php
declare(strict_types=1);
namespace HybridTM\Analysis\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\DSL\ThreatModel;

/** One simple path through the communication-link graph, source to target inclusive. */
final readonly class GraphPath
{
    /** @param list<string> $assetIds ordered source -> ... -> target */
    public function __construct(
        public array $assetIds,
        private ThreatModel $model,
        private DerivedTraits $derived,
    ) {
    }

    /** True if any node on the path (including both ends) carries any of the given traits. */
    public function anyNodeHasTrait(string ...$traits): bool
    {
        foreach ($this->assetIds as $assetId) {
            $asset = $this->model->getTechnicalAsset($assetId);
            if ($asset === null) {
                continue;
            }
            foreach ($traits as $trait) {
                if ($asset->hasTrait($trait) || in_array($trait, $this->derived->forAsset($assetId), true)) {
                    return true;
                }
            }
        }
        return false;
    }

    public function hopCount(): int
    {
        return max(0, count($this->assetIds) - 1);
    }

    /** Human-readable "web -> app -> db", using each asset's display name. */
    public function describe(): string
    {
        return implode(' -> ', array_map(
            fn (string $id): string => $this->model->getTechnicalAsset($id)?->name ?? $id,
            $this->assetIds,
        ));
    }
}
