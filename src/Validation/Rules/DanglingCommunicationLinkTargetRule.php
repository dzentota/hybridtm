<?php
declare(strict_types=1);
namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/** A communication link targets a technical asset id that does not exist (§3.6). */
final class DanglingCommunicationLinkTargetRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/dangling-communication-link-target';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        foreach ($model->getTechnicalAssets() as $sourceId => $asset) {
            foreach ($asset->communicationLinks as $link) {
                if ($model->getTechnicalAsset($link->targetAssetId) === null) {
                    yield ValidationIssue::error(
                        $this->code(),
                        "Communication link \"{$link->id}\" targets unknown technical asset \"{$link->targetAssetId}\".",
                        SubjectRef::flow($sourceId, $link->targetAssetId),
                    );
                }
            }
        }
    }
}
