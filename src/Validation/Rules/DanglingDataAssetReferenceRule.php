<?php

declare(strict_types=1);

namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/**
 * An asset or link references a data asset id that was never declared
 * (`dataAssetsProcessed`, `dataAssetsStored`, `dataSent`, `dataReceived`) (§3.6).
 */
final class DanglingDataAssetReferenceRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/dangling-data-asset-reference';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            foreach (['dataAssetsProcessed', 'dataAssetsStored'] as $field) {
                foreach ($asset->{$field} as $dataId) {
                    if ($model->getDataAsset($dataId) === null) {
                        yield ValidationIssue::error(
                            $this->code(),
                            "Technical asset \"{$assetId}\" references unknown data asset \"{$dataId}\" in {$field}.",
                            SubjectRef::component($assetId),
                        );
                    }
                }
            }

            foreach ($asset->communicationLinks as $link) {
                foreach (['dataSent', 'dataReceived'] as $field) {
                    foreach ($link->{$field} as $dataId) {
                        if ($model->getDataAsset($dataId) === null) {
                            yield ValidationIssue::error(
                                $this->code(),
                                "Communication link \"{$link->id}\" references unknown data asset \"{$dataId}\" in {$field}.",
                                SubjectRef::flow($assetId, $link->targetAssetId),
                            );
                        }
                    }
                }
            }
        }
    }
}
