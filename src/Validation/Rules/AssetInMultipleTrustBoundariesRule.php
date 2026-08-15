<?php
declare(strict_types=1);
namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/** A technical asset is listed inside two (or more) trust boundaries at once (§3.6). */
final class AssetInMultipleTrustBoundariesRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/asset-in-multiple-trust-boundaries';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        /** @var array<string, list<string>> */
        $boundariesByAsset = [];
        foreach ($model->getTrustBoundaries() as $boundaryId => $boundary) {
            foreach ($boundary->technicalAssetsInside as $assetId) {
                $boundariesByAsset[$assetId][] = $boundaryId;
            }
        }

        foreach ($boundariesByAsset as $assetId => $boundaryIds) {
            if (count($boundaryIds) > 1) {
                yield ValidationIssue::error(
                    $this->code(),
                    "Technical asset \"{$assetId}\" is inside multiple trust boundaries: "
                        . implode(', ', $boundaryIds) . '.',
                    SubjectRef::component($assetId),
                );
            }
        }
    }
}
