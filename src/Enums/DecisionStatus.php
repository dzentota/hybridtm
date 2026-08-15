<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/** Lifecycle state of a risk decision. */
enum DecisionStatus: string
{
    case Open          = 'open';
    case Accepted      = 'accepted';
    case Mitigated     = 'mitigated';
    case FalsePositive = 'false-positive';
    case Deferred      = 'deferred';

    /** Statuses that must carry an expiry date (ADR: risk acceptance is never permanent). */
    public function requiresExpiry(): bool
    {
        return $this === self::Accepted || $this === self::Deferred;
    }

    public function isResolved(): bool
    {
        return $this !== self::Open;
    }
}
