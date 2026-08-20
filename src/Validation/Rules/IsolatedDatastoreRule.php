<?php

declare(strict_types=1);

namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/** A datastore with no incoming communication links can never be reached — likely a missing link (§3.6). */
final class IsolatedDatastoreRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/isolated-datastore';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        $index = ModelIndex::build($model);

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            if ($asset->hasTrait('datastore') && $index->incomingLinks($assetId) === []) {
                yield ValidationIssue::warning(
                    $this->code(),
                    "Datastore \"{$assetId}\" has no incoming communication links and can never be reached.",
                    SubjectRef::component($assetId),
                );
            }
        }
    }
}
