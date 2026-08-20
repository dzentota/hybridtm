<?php

declare(strict_types=1);

namespace HybridTM\Analysis\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;

/**
 * `$ctx->model` — a convenience view over the `ThreatModel` for PHP rule
 * implementations. Unlike the sandboxed `Subjects\*` wrappers, this is
 * trusted code talking to the real model; the point of this class is
 * convenience methods (§4.6's `datastoresWithTrait`), not restriction.
 */
final readonly class RuleContextModel
{
    public function __construct(
        private ThreatModel $model,
        private DerivedTraits $derived,
    ) {
    }

    /** @return list<TechnicalAsset> assets that are datastores and carry the given trait (declared or derived) */
    public function datastoresWithTrait(string $trait): array
    {
        return $this->assetsWithTraits('datastore', $trait);
    }

    /** @return list<TechnicalAsset> assets carrying every given trait (declared or derived) */
    public function assetsWithTraits(string ...$traits): array
    {
        $result = [];
        foreach ($this->model->getTechnicalAssets() as $asset) {
            if ($this->hasAllTraits($asset, array_values($traits))) {
                $result[] = $asset;
            }
        }
        return $result;
    }

    public function hasTrait(TechnicalAsset $asset, string $trait): bool
    {
        return $asset->hasTrait($trait) || in_array($trait, $this->derived->forAsset($asset->id), true);
    }

    /** @param list<string> $traits */
    private function hasAllTraits(TechnicalAsset $asset, array $traits): bool
    {
        foreach ($traits as $trait) {
            if (!$this->hasTrait($asset, $trait)) {
                return false;
            }
        }
        return true;
    }

    public function unwrap(): ThreatModel
    {
        return $this->model;
    }
}
