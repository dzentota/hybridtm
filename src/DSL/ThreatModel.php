<?php
declare(strict_types=1);
namespace HybridTM\DSL;

use HybridTM\Enums\BusinessCriticality;

class ThreatModel
{
    public string $description = '';
    public string $author = '';
    public string $date = '';
    public BusinessCriticality $businessCriticality = BusinessCriticality::Important;
    public string $managementSummaryComment = '';

    /** @var DataAsset[] keyed by id */
    private array $dataAssets = [];

    /** @var TechnicalAsset[] keyed by id */
    private array $technicalAssets = [];

    /** @var TrustBoundary[] keyed by id */
    private array $trustBoundaries = [];

    public function __construct(public readonly string $title) {}

    public function addDataAsset(DataAsset $asset): static
    {
        $this->dataAssets[$asset->id] = $asset;
        return $this;
    }

    public function addTechnicalAsset(TechnicalAsset $asset): static
    {
        $this->technicalAssets[$asset->id] = $asset;
        return $this;
    }

    public function addTrustBoundary(TrustBoundary $boundary): static
    {
        $this->trustBoundaries[$boundary->id] = $boundary;
        return $this;
    }

    /** @return DataAsset[] */
    public function getDataAssets(): array { return $this->dataAssets; }

    /** @return TechnicalAsset[] */
    public function getTechnicalAssets(): array { return $this->technicalAssets; }

    /** @return TrustBoundary[] */
    public function getTrustBoundaries(): array { return $this->trustBoundaries; }

    public function getDataAsset(string $id): ?DataAsset { return $this->dataAssets[$id] ?? null; }
    public function getTechnicalAsset(string $id): ?TechnicalAsset { return $this->technicalAssets[$id] ?? null; }
}
