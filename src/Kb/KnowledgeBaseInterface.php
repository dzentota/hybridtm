<?php
declare(strict_types=1);
namespace HybridTM\Kb;

/**
 * Read-only view over the merged knowledge base (core KB + cloud packs +
 * organisation overrides). Implementations must be immutable and fast:
 * the analyzer queries them once per rule per subject.
 */
interface KnowledgeBaseInterface
{
    public function version(): string;

    public function has(Kind $kind, string $id): bool;

    /** @return array<string, mixed>|null resolved entity spec, `extends` already applied */
    public function get(Kind $kind, string $id): ?array;

    /** @return list<string> ids of every entity of a kind */
    public function ids(Kind $kind): array;

    /**
     * Rules applicable to a subject carrying the given traits, ordered by
     * descending priority. Filtering by trait here is what keeps the engine
     * from evaluating every rule against every node.
     *
     * @param list<string> $traits
     * @return list<string> rule ids
     */
    public function rulesFor(RuleScope $scope, array $traits = []): array;

    /** @return list<string> component ids in a category */
    public function componentsByCategory(string $category): array;
}
