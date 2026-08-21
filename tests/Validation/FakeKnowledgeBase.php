<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation;

use HybridTM\Kb\Kind;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Kb\RuleScope;

/** Minimal in-memory fake for tests that need a `KnowledgeBaseInterface`. */
final class FakeKnowledgeBase implements KnowledgeBaseInterface
{
    /** @var array<string, array<string, mixed>> */
    private array $components = [];

    public function __construct(private string $kbVersion = '1.0.0')
    {
    }

    /** @param array<string, mixed> $spec */
    public function withComponent(string $id, array $spec): static
    {
        $this->components[$id] = $spec;
        return $this;
    }

    public function version(): string
    {
        return $this->kbVersion;
    }

    public function has(Kind $kind, string $id): bool
    {
        return $kind === Kind::Component && isset($this->components[$id]);
    }

    public function get(Kind $kind, string $id): ?array
    {
        return $kind === Kind::Component ? ($this->components[$id] ?? null) : null;
    }

    public function ids(Kind $kind): array
    {
        return $kind === Kind::Component ? array_keys($this->components) : [];
    }

    public function rulesFor(RuleScope $scope, array $traits = []): array
    {
        return [];
    }

    public function componentsByCategory(string $category): array
    {
        return [];
    }
}
