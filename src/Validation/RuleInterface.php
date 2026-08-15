<?php
declare(strict_types=1);
namespace HybridTM\Validation;

use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;

/**
 * A single model-quality check. Implementations must be stateless so the
 * validator can reuse them across runs.
 */
interface RuleInterface
{
    public function code(): string;

    /** @return iterable<ValidationIssue> */
    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable;
}
