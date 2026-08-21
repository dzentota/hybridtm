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

    /** @var Question[] keyed by id */
    private array $questions = [];

    /** @var AbuseCase[] keyed by id */
    private array $abuseCases = [];

    /** @var SecurityRequirement[] keyed by id */
    private array $securityRequirements = [];

    /** @var SharedRuntime[] keyed by id */
    private array $sharedRuntimes = [];

    /** @var IndividualRiskCategory[] keyed by id */
    private array $individualRiskCategories = [];

    /** @var RiskTracking[] keyed by syntheticRiskId */
    private array $riskTracking = [];

    public function __construct(public readonly string $title)
    {
    }

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

    public function addQuestion(Question $question): static
    {
        $this->questions[$question->id] = $question;
        return $this;
    }

    public function addAbuseCase(AbuseCase $abuseCase): static
    {
        $this->abuseCases[$abuseCase->id] = $abuseCase;
        return $this;
    }

    public function addSecurityRequirement(SecurityRequirement $requirement): static
    {
        $this->securityRequirements[$requirement->id] = $requirement;
        return $this;
    }

    public function addSharedRuntime(SharedRuntime $runtime): static
    {
        $this->sharedRuntimes[$runtime->id] = $runtime;
        return $this;
    }

    public function addIndividualRiskCategory(IndividualRiskCategory $category): static
    {
        $this->individualRiskCategories[$category->id] = $category;
        return $this;
    }

    public function addRiskTracking(RiskTracking $tracking): static
    {
        $this->riskTracking[$tracking->syntheticRiskId] = $tracking;
        return $this;
    }

    /** @return DataAsset[] */
    public function getDataAssets(): array
    {
        return $this->dataAssets;
    }

    /** @return TechnicalAsset[] */
    public function getTechnicalAssets(): array
    {
        return $this->technicalAssets;
    }

    /** @return TrustBoundary[] */
    public function getTrustBoundaries(): array
    {
        return $this->trustBoundaries;
    }

    /** @return Question[] */
    public function getQuestions(): array
    {
        return $this->questions;
    }

    /** @return AbuseCase[] */
    public function getAbuseCases(): array
    {
        return $this->abuseCases;
    }

    /** @return SecurityRequirement[] */
    public function getSecurityRequirements(): array
    {
        return $this->securityRequirements;
    }

    /** @return SharedRuntime[] */
    public function getSharedRuntimes(): array
    {
        return $this->sharedRuntimes;
    }

    /** @return IndividualRiskCategory[] */
    public function getIndividualRiskCategories(): array
    {
        return $this->individualRiskCategories;
    }

    /** @return RiskTracking[] */
    public function getRiskTracking(): array
    {
        return $this->riskTracking;
    }

    public function getDataAsset(string $id): ?DataAsset
    {
        return $this->dataAssets[$id] ?? null;
    }
    public function getTechnicalAsset(string $id): ?TechnicalAsset
    {
        return $this->technicalAssets[$id] ?? null;
    }

    public function getAbuseCase(string $id): ?AbuseCase
    {
        return $this->abuseCases[$id] ?? null;
    }
}
