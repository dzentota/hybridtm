<?php
declare(strict_types=1);
namespace HybridTM\DSL;

/** A project-level security requirement, e.g. "Corporate firewall in place" (§3.1). */
class SecurityRequirement
{
    public function __construct(
        public readonly string $id,
        public string $description = '',
    ) {
    }
}
