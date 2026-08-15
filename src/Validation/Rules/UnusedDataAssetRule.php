<?php
declare(strict_types=1);
namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/** A declared data asset is never processed, stored, sent or received by anything (§3.6). */
final class UnusedDataAssetRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/unused-data-asset';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        $used = [];
        foreach ($model->getTechnicalAssets() as $asset) {
            foreach ([...$asset->dataAssetsProcessed, ...$asset->dataAssetsStored] as $dataId) {
                $used[$dataId] = true;
            }
            foreach ($asset->communicationLinks as $link) {
                foreach ([...$link->dataSent, ...$link->dataReceived] as $dataId) {
                    $used[$dataId] = true;
                }
            }
        }

        foreach (array_keys($model->getDataAssets()) as $dataId) {
            if (!isset($used[$dataId])) {
                yield ValidationIssue::info(
                    $this->code(),
                    "Data asset \"{$dataId}\" is declared but never processed, stored or transmitted.",
                    SubjectRef::dataAsset($dataId),
                );
            }
        }
    }
}
