<?php

declare(strict_types=1);

namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/**
 * A technical asset does not belong to any trust boundary (§3.6).
 *
 * Only fires once the model actually declares at least one trust boundary —
 * a model with none yet is simply unstarted, not defective, and flagging
 * every asset would be pure noise.
 */
final class AssetOutsideTrustBoundaryRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/asset-outside-trust-boundary';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        if ($model->getTrustBoundaries() === []) {
            return;
        }

        $index = ModelIndex::build($model);

        foreach (array_keys($model->getTechnicalAssets()) as $assetId) {
            if ($index->boundaryOf($assetId) === null) {
                yield ValidationIssue::warning(
                    $this->code(),
                    "Technical asset \"{$assetId}\" does not belong to any trust boundary.",
                    SubjectRef::component($assetId),
                );
            }
        }
    }
}
