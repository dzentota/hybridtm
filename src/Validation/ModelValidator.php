<?php

declare(strict_types=1);

namespace HybridTM\Validation;

use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;

/** Runs every registered check and collects the full set of issues (§3.6, T-1.8). */
final class ModelValidator implements ModelValidatorInterface
{
    private ValidatorRegistry $registry;

    public function __construct(?ValidatorRegistry $registry = null)
    {
        $this->registry = $registry ?? ValidatorRegistry::default();
    }

    public function validate(ThreatModel $model, ?KnowledgeBaseInterface $kb = null): ValidationReport
    {
        $report = new ValidationReport();

        foreach ($this->registry->all() as $rule) {
            foreach ($rule->check($model, $kb) as $issue) {
                $report->add($issue);
            }
        }

        return $report;
    }
}
