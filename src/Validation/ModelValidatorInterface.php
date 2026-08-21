<?php

declare(strict_types=1);

namespace HybridTM\Validation;

use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;

interface ModelValidatorInterface
{
    public function validate(ThreatModel $model, ?KnowledgeBaseInterface $kb = null): ValidationReport;
}
