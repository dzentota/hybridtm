<?php

declare(strict_types=1);

namespace App\Policy;

final readonly class PolicyViolation
{
    public function __construct(
        public string $policyId,
        public string $description,
        public string $subject,
        public string $reason,
    ) {
    }
}
