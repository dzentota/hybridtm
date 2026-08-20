<?php

declare(strict_types=1);

namespace HybridTM\DSL;

/** A business-level abuse scenario the model should defend against (§3.1). */
class AbuseCase
{
    public function __construct(
        public readonly string $id,
        public string $description = '',
    ) {
    }
}
