<?php
declare(strict_types=1);
namespace HybridTM\Risk;

use HybridTM\DSL\RiskTracking;
use HybridTM\Enums\DecisionStatus;

/**
 * A decision taken on a finding (§5.6, T-5.6) — accept, mitigate, dismiss
 * as false positive, or defer. Serializes to/from the `RiskTracking` DSL
 * entity so decisions live in `threat-model.php` and git stays the single
 * source of truth for them too, closing the gap the original README
 * describes as "currently requires manual YAML merge".
 *
 * Both validity rules the plan calls for are enforced right here, at
 * construction, rather than only checked later: an `Accepted`/`Deferred`
 * decision without an expiry is rejected immediately (risk acceptance is
 * never permanent), and a justification under 20 characters is rejected
 * too (a decision without a real reason is not a decision).
 */
final readonly class RiskDecision
{
    public function __construct(
        public string $findingStableId,
        public DecisionStatus $status,
        public string $justification,
        public ?string $ticket,
        public ?\DateTimeImmutable $expiresAt,
        public string $decidedBy,
        public \DateTimeImmutable $decidedAt,
    ) {
        if ($status->requiresExpiry() && $expiresAt === null) {
            throw new \InvalidArgumentException(
                "RiskDecision for \"{$findingStableId}\": status {$status->value} requires an expiresAt — risk acceptance is never permanent.",
            );
        }
        if (mb_strlen($justification) < 20) {
            throw new \InvalidArgumentException(
                "RiskDecision for \"{$findingStableId}\": justification must be at least 20 characters.",
            );
        }
    }

    public function toRiskTracking(): RiskTracking
    {
        $tracking = new RiskTracking($this->findingStableId);
        $tracking->status = $this->status;
        $tracking->justification = $this->justification;
        $tracking->ticket = $this->ticket ?? '';
        $tracking->expiresAt = $this->expiresAt?->format('Y-m-d');
        $tracking->checkedBy = $this->decidedBy;
        $tracking->date = $this->decidedAt->format('Y-m-d');

        return $tracking;
    }

    public static function fromRiskTracking(RiskTracking $tracking): self
    {
        return new self(
            findingStableId: $tracking->syntheticRiskId,
            status: $tracking->status,
            justification: $tracking->justification,
            ticket: $tracking->ticket !== '' ? $tracking->ticket : null,
            expiresAt: $tracking->expiresAt !== null ? new \DateTimeImmutable($tracking->expiresAt) : null,
            decidedBy: $tracking->checkedBy,
            // Epoch fallback keeps this deterministic (no implicit "now"
            // read) when a hand-edited RiskTracking has no date set.
            decidedAt: $tracking->date !== '' ? new \DateTimeImmutable($tracking->date) : new \DateTimeImmutable('@0'),
        );
    }
}
