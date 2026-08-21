<?php

declare(strict_types=1);

namespace HybridTM\Attributes;

/**
 * Links a class or method to an Abuser Story id declared in the threat model
 * (`AbuseCase` / abuseCases). Place next to #[Mitigation] / #[DataFlow] so
 * story coverage can verify that required CWEs are mitigated in code.
 */
#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::TARGET_CLASS | \Attribute::TARGET_FUNCTION | \Attribute::IS_REPEATABLE)]
final class AbuserStory
{
    public function __construct(
        public readonly string $id,
    ) {
    }
}
