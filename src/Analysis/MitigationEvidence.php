<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\Enums\MitigationStatus;

/**
 * A control found in the codebase via #[Mitigation]. This is the feature
 * that distinguishes HybridTM from diagram-only tools: a countermeasure is
 * evidenced by code, not by someone ticking a box.
 */
final readonly class MitigationEvidence implements \JsonSerializable
{
    public function __construct(
        public string $cwe,
        public string $description,
        public MitigationStatus $status,
        public ?CodeLocation $location = null,
    ) {
    }

    /** @return array{cwe: string, description: string, status: string, location: CodeLocation|null} */
    public function jsonSerialize(): array
    {
        return [
            'cwe' => $this->cwe,
            'description' => $this->description,
            'status' => $this->status->value,
            'location' => $this->location,
        ];
    }
}
