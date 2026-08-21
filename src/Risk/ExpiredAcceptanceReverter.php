<?php

declare(strict_types=1);

namespace HybridTM\Risk;

use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\DecisionStatus;

/**
 * The background half of "risk acceptance is never permanent" (§5.6,
 * T-5.7): flips any `Accepted`/`Deferred` `RiskTracking` entry whose
 * `expiresAt` has passed back to `Open`, so it reappears in the register
 * for someone to act on.
 *
 * `$now` is always supplied by the caller rather than read internally
 * (`new DateTimeImmutable()` with no args) — the actual periodic
 * invocation (a cron job, a queue worker) is what reads the wall clock;
 * this class stays a pure, deterministic function of its inputs.
 */
final class ExpiredAcceptanceReverter
{
    /** @return list<RiskTracking> the entries that were just reverted, for a notification digest (T-9.9 territory, not built here) */
    public function revertExpired(ThreatModel $model, \DateTimeImmutable $now): array
    {
        $reverted = [];

        foreach ($model->getRiskTracking() as $tracking) {
            if (!$tracking->status->requiresExpiry() || $tracking->expiresAt === null) {
                continue;
            }

            if (new \DateTimeImmutable($tracking->expiresAt) < $now) {
                $tracking->status = DecisionStatus::Open;
                $reverted[] = $tracking;
            }
        }

        return $reverted;
    }
}
