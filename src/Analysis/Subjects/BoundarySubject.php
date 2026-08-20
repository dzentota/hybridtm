<?php

declare(strict_types=1);

namespace HybridTM\Analysis\Subjects;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\DSL\PropertyBag;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;

/** The `boundary` variable exposed to boundary-scope rule expressions (§4.6). */
final readonly class BoundarySubject
{
    public string $id;
    public string $name;
    public string $type;
    /** @var list<string> */
    public array $technicalAssetIds;
    public PropertyBag $props;

    public function __construct(
        private TrustBoundary $boundary,
        private ThreatModel $model,
        private DerivedTraits $derived,
    ) {
        $this->id = $boundary->id;
        $this->name = $boundary->name;
        $this->type = $boundary->type->value;
        $this->technicalAssetIds = array_values($boundary->technicalAssetsInside);
        $this->props = $boundary->properties;
    }

    /** True if any contained asset declares or derives any of the given traits (OR semantics). */
    public function anyAssetHasTrait(string ...$traits): bool
    {
        foreach ($this->technicalAssetIds as $assetId) {
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

    public function assetCount(): int
    {
        return count($this->technicalAssetIds);
    }
}
