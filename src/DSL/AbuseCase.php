<?php

declare(strict_types=1);

namespace HybridTM\DSL;

use HybridTM\Enums\AbuseCaseStatus;

/**
 * A business-level abuser / misuser story the model should defend against.
 * Threagile export still uses `abuse_cases: { id: description }`; richer
 * fields live in the canonical JSON model and PHP DSL.
 */
class AbuseCase
{
    public string $asA = '';
    public string $iWant = '';
    public string $soThat = '';
    public ?string $actorId = null;

    /** @var list<string> */
    public array $assetIds = [];

    /** @var list<string> */
    public array $dataFlowIds = [];

    /** @var list<string> */
    public array $dataAssetIds = [];

    /** @var list<string> KB threat IDs (THREAT-*) */
    public array $threatIds = [];

    /** @var list<string> e.g. CWE-307 — when empty, derived from KB threats at verify time */
    public array $requiredCwes = [];

    public AbuseCaseStatus $status = AbuseCaseStatus::Open;

    public function __construct(
        public readonly string $id,
        public string $description = '',
    ) {
    }

    /** Prefer agile narrative; fall back to free-text description. */
    public function narrative(): string
    {
        if ($this->asA !== '' || $this->iWant !== '' || $this->soThat !== '') {
            $parts = [];
            if ($this->asA !== '') {
                $parts[] = 'As a ' . $this->asA;
            }
            if ($this->iWant !== '') {
                $parts[] = 'I want to ' . $this->iWant;
            }
            if ($this->soThat !== '') {
                $parts[] = 'so that ' . $this->soThat;
            }

            return implode(', ', $parts);
        }

        return $this->description;
    }
}
