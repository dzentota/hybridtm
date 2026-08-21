<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\Compiler\DiscoveredAbuserStoryRef;
use HybridTM\Compiler\DiscoveredMitigation;
use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\AbuseCaseStatus;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Kb\Kind;
use HybridTM\Kb\KnowledgeBaseInterface;

/**
 * Verifies each Abuser Story against #[AbuserStory] + #[Mitigation] evidence
 * discovered in source, and against structural links in the model.
 */
final class StoryCoverageAnalyzer
{
    /**
     * @param list<DiscoveredAbuserStoryRef> $abuserStoryRefs
     * @return list<StoryCoverage>
     */
    public function analyze(
        ThreatModel $model,
        KnowledgeBaseInterface $kb,
        ?MitigationIndex $mitigations,
        array $abuserStoryRefs = [],
    ): array {
        $mitigationList = $mitigations?->all() ?? [];
        $results = [];

        foreach ($model->getAbuseCases() as $case) {
            $results[] = $this->coverOne($case, $model, $kb, $mitigationList, $abuserStoryRefs);
        }

        return $results;
    }

    /**
     * @param list<DiscoveredMitigation> $mitigations
     * @param list<DiscoveredAbuserStoryRef> $abuserStoryRefs
     */
    private function coverOne(
        AbuseCase $case,
        ThreatModel $model,
        KnowledgeBaseInterface $kb,
        array $mitigations,
        array $abuserStoryRefs,
    ): StoryCoverage {
        $issues = $this->structuralIssues($case, $model, $kb);
        $required = $this->requiredCwes($case, $kb);

        if ($case->status === AbuseCaseStatus::Accepted) {
            return new StoryCoverage(
                storyId: $case->id,
                status: StoryCoverageStatus::Accepted,
                requiredCwes: $required,
                coveredCwes: $required,
                missingCwes: [],
                issues: $issues,
            );
        }

        if ($case->status === AbuseCaseStatus::Mitigated && $required === []) {
            return new StoryCoverage(
                storyId: $case->id,
                status: StoryCoverageStatus::Covered,
                requiredCwes: [],
                coveredCwes: [],
                missingCwes: [],
                issues: $issues,
            );
        }

        $covered = [];
        foreach ($required as $cwe) {
            if ($this->isCweCoveredForStory($case->id, $cwe, $mitigations, $abuserStoryRefs)) {
                $covered[] = $cwe;
            }
        }

        $missing = array_values(array_diff($required, $covered));

        if ($required === []) {
            $status = $issues === [] ? StoryCoverageStatus::Uncovered : StoryCoverageStatus::Uncovered;
            // No CWEs to verify: treat as uncovered unless story marked mitigated.
            if ($case->status === AbuseCaseStatus::Mitigated) {
                $status = StoryCoverageStatus::Covered;
            }
        } elseif ($missing === []) {
            $status = StoryCoverageStatus::Covered;
        } elseif ($covered === []) {
            $status = StoryCoverageStatus::Uncovered;
        } else {
            $status = StoryCoverageStatus::Partial;
        }

        return new StoryCoverage(
            storyId: $case->id,
            status: $status,
            requiredCwes: $required,
            coveredCwes: $covered,
            missingCwes: $missing,
            issues: $issues,
        );
    }

    /**
     * @param list<DiscoveredMitigation> $mitigations
     * @param list<DiscoveredAbuserStoryRef> $abuserStoryRefs
     */
    private function isCweCoveredForStory(
        string $storyId,
        string $cwe,
        array $mitigations,
        array $abuserStoryRefs,
    ): bool {
        foreach ($mitigations as $m) {
            if (
                $m->cwe === $cwe
                && $m->status === MitigationStatus::Mitigated
                && in_array($storyId, $m->abuserStoryIds, true)
            ) {
                return true;
            }
        }

        // Also accept: story ref on same context that lists the CWE as sibling
        // (covers ordering where we only have refs, not mitigations with story ids).
        foreach ($abuserStoryRefs as $ref) {
            if ($ref->storyId === $storyId && in_array($cwe, $ref->siblingCwes, true)) {
                foreach ($mitigations as $m) {
                    if (
                        $m->cwe === $cwe
                        && $m->status === MitigationStatus::Mitigated
                        && $m->context === $ref->context
                    ) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /** @return list<string> */
    private function requiredCwes(AbuseCase $case, KnowledgeBaseInterface $kb): array
    {
        $cwes = $case->requiredCwes;
        foreach ($case->threatIds as $threatId) {
            $threat = $kb->get(Kind::Threat, $threatId);
            if ($threat === null) {
                continue;
            }
            foreach ($threat['standards']['cwe'] ?? [] as $num) {
                $cwes[] = 'CWE-' . (int) $num;
            }
        }

        $cwes = array_values(array_unique($cwes));
        sort($cwes);

        return $cwes;
    }

    /** @return list<string> */
    private function structuralIssues(AbuseCase $case, ThreatModel $model, KnowledgeBaseInterface $kb): array
    {
        $issues = [];

        if ($case->actorId !== null && $case->actorId !== '') {
            $actor = $model->getTechnicalAsset($case->actorId);
            if ($actor === null) {
                $issues[] = "Unknown actorId '{$case->actorId}'";
            } elseif (!$actor->hasTrait('threat_actor')) {
                $issues[] = "Actor '{$case->actorId}' lacks threat_actor trait";
            }
        }

        foreach ($case->assetIds as $assetId) {
            if ($model->getTechnicalAsset($assetId) === null) {
                $issues[] = "Unknown assetId '{$assetId}'";
            }
        }

        foreach ($case->dataAssetIds as $dataId) {
            if ($model->getDataAsset($dataId) === null) {
                $issues[] = "Unknown dataAssetId '{$dataId}'";
            }
        }

        $knownFlowIds = [];
        foreach ($model->getTechnicalAssets() as $asset) {
            foreach ($asset->communicationLinks as $linkId => $_) {
                $knownFlowIds[$linkId] = true;
            }
        }
        foreach ($case->dataFlowIds as $flowId) {
            if (!isset($knownFlowIds[$flowId])) {
                $issues[] = "Unknown dataFlowId '{$flowId}'";
            }
        }

        foreach ($case->threatIds as $threatId) {
            if ($kb->get(Kind::Threat, $threatId) === null) {
                $issues[] = "Unknown threatId '{$threatId}'";
            }
        }

        return $issues;
    }
}
