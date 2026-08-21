<?php

declare(strict_types=1);

namespace App\Message;

/**
 * Dispatched by `POST /model-versions/{id}/analyze/deep` (T-6.5): a
 * Threagile run takes seconds, so it happens off the request thread,
 * unlike the synchronous `/analyze` endpoint that runs RuleEngine inline.
 */
final readonly class RunDeepAnalysis
{
    public function __construct(
        public string $modelVersionId,
    ) {
    }
}
