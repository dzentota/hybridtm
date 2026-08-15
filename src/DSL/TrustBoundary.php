<?php
declare(strict_types=1);
namespace HybridTM\DSL;

use HybridTM\Enums\TrustBoundaryType;

class TrustBoundary
{
    public string $description = '';
    /** @var string[] IDs of TechnicalAssets inside */
    public array $technicalAssetsInside = [];
    /** @var string[] IDs of nested TrustBoundaries */
    public array $trustBoundariesNested = [];
    /** @var string[] */
    public array $tags = [];
    /** KB component properties (§3.2) — never serialized to Threagile YAML. */
    public PropertyBag $properties;

    public function __construct(
        public readonly string $id,
        public string $name = '',
        public TrustBoundaryType $type = TrustBoundaryType::NetworkOnPrem,
    ) {
        if ($this->name === '') $this->name = $this->id;
        $this->properties = new PropertyBag();
    }

    public function addAssets(string ...$assetIds): static
    {
        foreach ($assetIds as $id) {
            if (!in_array($id, $this->technicalAssetsInside, true)) {
                $this->technicalAssetsInside[] = $id;
            }
        }
        return $this;
    }
}
