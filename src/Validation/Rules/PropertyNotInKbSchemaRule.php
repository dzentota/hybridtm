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
 * A `PropertyBag` key on an asset expanded from a KB component (§6.3 marker
 * tier, see `KbComponentTag`) is not declared in that component's property
 * schema (§3.6). Silent without a knowledge base or without a marker tag —
 * there is nothing to check against.
 */
final class PropertyNotInKbSchemaRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/property-not-in-kb-schema';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        if ($kb === null) {
            return;
        }

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            $ref = KbComponentTag::fromTags($asset->tags);
            if ($ref === null || !$kb->has(Kind::Component, $ref->componentId)) {
                continue;
            }

            $spec = $kb->get(Kind::Component, $ref->componentId) ?? [];
            $allowed = array_map(
                static fn (array $property): string => (string) $property['id'],
                $spec['properties'] ?? [],
            );

            foreach (array_keys($asset->properties->toArray()) as $key) {
                if (!in_array($key, $allowed, true)) {
                    yield ValidationIssue::warning(
                        $this->code(),
                        "Technical asset \"{$assetId}\" sets property \"{$key}\" which is not declared "
                            . "by KB component \"{$ref->componentId}\".",
                        SubjectRef::component($assetId),
                    );
                }
            }
        }
    }
}
