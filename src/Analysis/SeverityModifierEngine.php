<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\SubjectKind;

/**
 * Score phase contextual modifiers (§5.3, T-3.8): nudges a Finding's
 * likelihood/impact up or down by whole scale steps based on context the
 * base threat/rule can't see on its own — `Finding::withSeverity()` then
 * recomputes severity from the adjusted values via the same
 * `Severity::calculate()` formula used everywhere else.
 *
 * Implements 5 of the plan's 8 modifiers. The other 3 need data this
 * engine version doesn't have yet, and are deliberately not approximated
 * with a shaky heuristic:
 *  - "behind_waf and a web-class threat" -> likelihood -1: KB `Threat`
 *    entities have no category/class field to test "web-class" against
 *    (§4.4's schema has `stride`, not a threat family).
 *  - "partially applied countermeasure (in-progress)" -> likelihood -1:
 *    needs #[Mitigation] status from the AST scanner, which
 *    AnalyzerInterface::analyze() has no parameter for (same gap noted
 *    in RuleEngine's Suppress phase).
 *  - "customDevelopedParts: false for injection threats" -> likelihood -1:
 *    same missing "threat family" classification as the WAF modifier.
 */
final class SeverityModifierEngine
{
    public function apply(Finding $finding, ThreatModel $model, ModelIndex $index, DerivedTraits $derived): Finding
    {
        $likelihoodSteps = 0;
        $impactSteps = 0;

        $assetIds = $this->assetIdsForSubject($finding->subject, $model);

        foreach ($assetIds as $assetId) {
            if ($this->isInternetReachable($assetId, $derived)) {
                ++$likelihoodSteps;
                break;
            }
        }

        if ($model->getTrustBoundaries() !== []) {
            foreach ($assetIds as $assetId) {
                if ($index->boundaryOf($assetId) === null) {
                    ++$likelihoodSteps;
                    break;
                }
            }
        }

        $dataIds = $this->dataIdsForSubject($finding->subject, $model);

        foreach ($dataIds as $dataId) {
            if ($model->getDataAsset($dataId)?->confidentiality === Confidentiality::StrictlyConfidential) {
                ++$impactSteps;
                break;
            }
        }

        if ($model->businessCriticality === BusinessCriticality::MissionCritical) {
            ++$impactSteps;
        }

        foreach ($dataIds as $dataId) {
            if ($model->getDataAsset($dataId)?->quantity === Quantity::VeryMany) {
                ++$impactSteps;
                break;
            }
        }

        if ($likelihoodSteps === 0 && $impactSteps === 0) {
            return $finding;
        }

        return $finding->withSeverity(
            $finding->likelihood->shift($likelihoodSteps),
            $finding->impact->shift($impactSteps),
        );
    }

    private function isInternetReachable(string $assetId, DerivedTraits $derived): bool
    {
        return in_array('internet_reachable', $derived->forAsset($assetId), true);
    }

    /** @return list<string> */
    private function assetIdsForSubject(SubjectRef $subject, ThreatModel $model): array
    {
        return match ($subject->kind) {
            SubjectKind::Component => [$subject->primaryId],
            SubjectKind::Flow      => [$subject->primaryId, (string) $subject->secondaryId],
            SubjectKind::Boundary  => $model->getTrustBoundaries()[$subject->primaryId]->technicalAssetsInside ?? [],
            SubjectKind::DataAsset, SubjectKind::Model => [],
        };
    }

    /** @return list<string> */
    private function dataIdsForSubject(SubjectRef $subject, ThreatModel $model): array
    {
        if ($subject->kind === SubjectKind::Component) {
            $asset = $model->getTechnicalAsset($subject->primaryId);
            return $asset === null ? [] : [...$asset->dataAssetsProcessed, ...$asset->dataAssetsStored];
        }

        if ($subject->kind === SubjectKind::Flow) {
            $link = $this->findLinkTo($model->getTechnicalAsset($subject->primaryId), (string) $subject->secondaryId);
            return $link === null ? [] : [...$link->dataSent, ...$link->dataReceived];
        }

        return [];
    }

    private function findLinkTo(?\HybridTM\DSL\TechnicalAsset $source, string $targetId): ?\HybridTM\DSL\CommunicationLink
    {
        if ($source === null) {
            return null;
        }
        foreach ($source->communicationLinks as $link) {
            if ($link->targetAssetId === $targetId) {
                return $link;
            }
        }
        return null;
    }
}
