<?php

declare(strict_types=1);

namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/**
 * The same id is used for two entities of different kinds (e.g. a technical
 * asset and a trust boundary both called "db"). Each DSL collection is
 * keyed by id internally, so a clash *within* one collection silently
 * overwrites the earlier entry instead of surviving to be checked here —
 * this rule catches the cross-collection case, which is ambiguous for
 * anything that references ids generically (layout files, `SubjectRef`) (§3.6).
 */
final class DuplicateIdRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/duplicate-id';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        /** @var array<string, list<string>> id => kinds that use it */
        $kindsById = [];

        foreach (array_keys($model->getDataAssets()) as $id) {
            $kindsById[$id][] = 'data asset';
        }
        foreach (array_keys($model->getTechnicalAssets()) as $id) {
            $kindsById[$id][] = 'technical asset';
        }
        foreach (array_keys($model->getTrustBoundaries()) as $id) {
            $kindsById[$id][] = 'trust boundary';
        }
        foreach (array_keys($model->getSharedRuntimes()) as $id) {
            $kindsById[$id][] = 'shared runtime';
        }

        foreach ($kindsById as $id => $kinds) {
            if (count($kinds) > 1) {
                yield ValidationIssue::error(
                    $this->code(),
                    "Id \"{$id}\" is used by more than one entity: " . implode(', ', $kinds) . '.',
                    SubjectRef::component($id),
                );
            }
        }
    }
}
