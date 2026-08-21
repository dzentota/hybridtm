<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

/** Coverage result for one Abuser Story in the model. */
final readonly class StoryCoverage implements \JsonSerializable
{
    /**
     * @param list<string> $requiredCwes
     * @param list<string> $coveredCwes
     * @param list<string> $missingCwes
     * @param list<string> $issues structural problems (unknown actor, etc.)
     */
    public function __construct(
        public string $storyId,
        public StoryCoverageStatus $status,
        public array $requiredCwes = [],
        public array $coveredCwes = [],
        public array $missingCwes = [],
        public array $issues = [],
    ) {
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'storyId' => $this->storyId,
            'status' => $this->status->value,
            'requiredCwes' => $this->requiredCwes,
            'coveredCwes' => $this->coveredCwes,
            'missingCwes' => $this->missingCwes,
            'issues' => $this->issues,
        ];
    }
}
