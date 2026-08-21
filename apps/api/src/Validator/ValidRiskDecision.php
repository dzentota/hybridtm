<?php

declare(strict_types=1);

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

/**
 * Mirrors HybridTM\Risk\RiskDecision's own constructor rule at the API
 * boundary: Accepted/Deferred without an expiresAt is rejected before it
 * ever reaches the domain object — risk acceptance is never permanent.
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
final class ValidRiskDecision extends Constraint
{
    public string $message = 'Status "{{ status }}" requires an expiresAt — risk acceptance is never permanent.';

    public function getTargets(): string
    {
        return self::CLASS_CONSTRAINT;
    }
}
