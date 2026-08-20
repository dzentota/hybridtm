<?php

declare(strict_types=1);

namespace HybridTM\DSL;

use HybridTM\Enums\DecisionStatus;

/**
 * A recorded decision against a specific risk (accept, mitigate, dismiss as
 * false positive, defer) — the mechanism the README admits is missing:
 * risk acceptance living in the model instead of a manual YAML edit (§3.1).
 */
class RiskTracking
{
    public DecisionStatus $status = DecisionStatus::Open;
    public string $justification = '';
    public string $ticket = '';
    public string $date = '';
    public string $checkedBy = '';
    public ?string $expiresAt = null;

    /** @param string $syntheticRiskId Threagile's synthetic risk id, or a Finding::$stableId. */
    public function __construct(public readonly string $syntheticRiskId)
    {
    }
}
