<?php

declare(strict_types=1);

namespace HybridTM\Kb;

/**
 * Immutable, in-memory `KnowledgeBaseInterface`: everything a `YamlKbLoader`
 * (or a future compiled-cache loader, T-2.4) produces after merging layers
 * and resolving `extends`.
 */
final class InMemoryKnowledgeBase implements KnowledgeBaseInterface
{
    /** @var array<string, array<string, array<string, mixed>>> kind => id => resolved spec (+ 'metadata') */
    private array $entities;

    private string $version;

    /** @var array<string, list<string>> ruleId => componentIds referencing it in spec.rules */
    private array $componentsByRule = [];

    /**
     * @param array<string, array<string, array<string, mixed>>> $entities kind value => id => resolved spec
     */
    public function __construct(array $entities, string $version)
    {
        $this->entities = $entities;
        $this->version = $version;

        foreach ($this->entities[Kind::Component->value] ?? [] as $componentId => $spec) {
            foreach ($spec['rules'] ?? [] as $ruleId) {
                $this->componentsByRule[$ruleId][] = $componentId;
            }
        }
    }

    public function version(): string
    {
        return $this->version;
    }

    public function has(Kind $kind, string $id): bool
    {
        return isset($this->entities[$kind->value][$id]);
    }

    public function get(Kind $kind, string $id): ?array
    {
        return $this->entities[$kind->value][$id] ?? null;
    }

    public function ids(Kind $kind): array
    {
        return array_keys($this->entities[$kind->value] ?? []);
    }

    public function rulesFor(RuleScope $scope, array $traits = []): array
    {
        $candidates = $this->ids(Kind::Rule);

        $inScope = array_values(array_filter(
            $candidates,
            fn (string $ruleId): bool => ($this->get(Kind::Rule, $ruleId)['scope'] ?? null) === $scope->value,
        ));

        if ($traits !== []) {
            $componentsWithTrait = [];
            foreach ($this->entities[Kind::Component->value] ?? [] as $componentId => $spec) {
                if (array_intersect($traits, $spec['traits'] ?? []) !== []) {
                    $componentsWithTrait[$componentId] = true;
                }
            }

            $inScope = array_values(array_filter(
                $inScope,
                function (string $ruleId) use ($componentsWithTrait): bool {
                    foreach ($this->componentsByRule[$ruleId] ?? [] as $componentId) {
                        if (isset($componentsWithTrait[$componentId])) {
                            return true;
                        }
                    }
                    return false;
                },
            ));
        }

        usort($inScope, function (string $a, string $b): int {
            $priorityA = $this->get(Kind::Rule, $a)['priority'] ?? 0;
            $priorityB = $this->get(Kind::Rule, $b)['priority'] ?? 0;
            return $priorityB <=> $priorityA ?: $a <=> $b;
        });

        return $inScope;
    }

    public function componentsByCategory(string $category): array
    {
        $result = [];
        foreach ($this->entities[Kind::Component->value] ?? [] as $componentId => $spec) {
            if (in_array($category, $spec['metadata']['categories'] ?? [], true)) {
                $result[] = $componentId;
            }
        }
        sort($result);
        return $result;
    }
}
