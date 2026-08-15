<?php
declare(strict_types=1);
namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/** Every id must be a stable slug (ADR-11): `^[a-z][a-z0-9-]{1,62}$` (§3.6). */
final class InvalidIdSlugRule implements RuleInterface
{
    private const PATTERN = '/^[a-z][a-z0-9-]{1,62}$/';

    public function code(): string
    {
        return 'validation/invalid-id-slug';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        foreach ($model->getDataAssets() as $id => $asset) {
            yield from $this->checkId($id, SubjectRef::dataAsset($id));
        }
        foreach ($model->getTechnicalAssets() as $id => $asset) {
            yield from $this->checkId($id, SubjectRef::component($id));
        }
        foreach ($model->getTrustBoundaries() as $id => $boundary) {
            yield from $this->checkId($id, SubjectRef::boundary($id));
        }
    }

    /** @return iterable<ValidationIssue> */
    private function checkId(string $id, SubjectRef $subject): iterable
    {
        if (!preg_match(self::PATTERN, $id)) {
            yield ValidationIssue::error(
                $this->code(),
                "Id \"{$id}\" does not match the required slug pattern " . self::PATTERN . '.',
                $subject,
            );
        }
    }
}
