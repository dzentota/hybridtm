<?php

declare(strict_types=1);

namespace HybridTM\DSL;

use HybridTM\Enums\RiskFunction;
use HybridTM\Enums\Stride;

/**
 * A custom risk category not covered by Threagile's 42 built-in rules
 * (§3.1). Field names mirror Threagile's `types.RiskCategory` so nothing is
 * lost when exchanging content with it.
 */
class IndividualRiskCategory
{
    public string $title = '';
    public string $description = '';
    public string $impact = '';
    public string $asvs = '';
    public string $cheatSheet = '';
    public string $action = '';
    public string $mitigation = '';
    public string $check = '';
    public string $detectionLogic = '';
    public string $riskAssessment = '';
    public string $falsePositives = '';
    public RiskFunction $function = RiskFunction::Operations;
    /** @var Stride[] */
    public array $stride = [];
    /** @var string[] e.g. ["CWE-311"] */
    public array $cwe = [];

    public function __construct(public readonly string $id)
    {
    }
}
