<?php

declare(strict_types=1);

namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\Kind;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/**
 * An asset was expanded from a KB component version the loaded knowledge
 * base no longer recognises (renamed, retired, or the pinned version is
 * simply absent from this KB build) (§3.6). Purely informational: the
 * model still works, but findings from that component's rules may be stale.
 */
final class UnknownKbComponentVersionRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/unknown-kb-component-version';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        if ($kb === null) {
            return;
        }

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            $ref = KbComponentTag::fromTags($asset->tags);
            if ($ref === null) {
                continue;
            }

            if (!$kb->has(Kind::Component, $ref->componentId)) {
                yield ValidationIssue::info(
                    $this->code(),
                    "Technical asset \"{$assetId}\" references unknown KB component \"{$ref->componentId}\".",
                    SubjectRef::component($assetId),
                );
                continue;
            }

            if ($ref->version === null) {
                continue;
            }

            $spec = $kb->get(Kind::Component, $ref->componentId) ?? [];
            $currentVersion = $spec['metadata']['version'] ?? $spec['version'] ?? null;

            if ($currentVersion !== null && $currentVersion !== $ref->version) {
                yield ValidationIssue::info(
                    $this->code(),
                    "Technical asset \"{$assetId}\" was expanded from KB component "
                        . "\"{$ref->componentId}\" version {$ref->version}, but the loaded "
                        . "knowledge base is at version {$currentVersion}.",
                    SubjectRef::component($assetId),
                );
            }
        }
    }
}
