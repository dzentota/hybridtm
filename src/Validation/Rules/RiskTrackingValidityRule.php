<?php
declare(strict_types=1);
namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/**
 * Risk acceptance is never permanent (§5.6/5.7): an `Accepted` or
 * `Deferred` `RiskTracking` entry without an `expiresAt` is rejected, and
 * — for any entry that actually records a decision (i.e. not `Open`, which
 * just means "not decided yet" and has nothing to justify) — a
 * justification under 20 characters is rejected too. Mirrors the same
 * two rules `RiskDecision`'s own constructor enforces, for models that
 * build `RiskTracking` directly in PHP DSL rather than through
 * `RiskDecision`.
 */
final class RiskTrackingValidityRule implements RuleInterface
{
    private const MIN_JUSTIFICATION_LENGTH = 20;

    public function code(): string
    {
        return 'validation/risk-tracking-validity';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        foreach ($model->getRiskTracking() as $syntheticRiskId => $tracking) {
            if ($tracking->status->requiresExpiry() && $tracking->expiresAt === null) {
                yield ValidationIssue::error(
                    $this->code(),
                    "Risk tracking \"{$syntheticRiskId}\" has status {$tracking->status->value} but no expiresAt — risk acceptance is never permanent.",
                    SubjectRef::model(),
                );
            }

            if ($tracking->status !== DecisionStatus::Open && mb_strlen($tracking->justification) < self::MIN_JUSTIFICATION_LENGTH) {
                yield ValidationIssue::error(
                    $this->code(),
                    "Risk tracking \"{$syntheticRiskId}\" has a justification shorter than " . self::MIN_JUSTIFICATION_LENGTH . ' characters.',
                    SubjectRef::model(),
                );
            }
        }
    }
}
