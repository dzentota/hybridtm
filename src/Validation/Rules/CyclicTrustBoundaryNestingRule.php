<?php

declare(strict_types=1);

namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/** `trustBoundariesNested` forms a cycle, which has no sane containment meaning (§3.6). */
final class CyclicTrustBoundaryNestingRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/cyclic-trust-boundary-nesting';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        $boundaries = $model->getTrustBoundaries();
        $reportedCycles = [];
        $globallyVisited = [];

        foreach (array_keys($boundaries) as $startId) {
            if (isset($globallyVisited[$startId])) {
                continue;
            }

            $cycle = $this->findCycle($boundaries, $startId, [], $globallyVisited);
            if ($cycle !== null) {
                $sorted = array_unique($cycle);
                sort($sorted);
                $key = implode(',', $sorted);
                if (!isset($reportedCycles[$key])) {
                    $reportedCycles[$key] = true;
                    yield ValidationIssue::error(
                        $this->code(),
                        'Cyclic trust boundary nesting detected: ' . implode(' -> ', $cycle) . '.',
                        SubjectRef::boundary($cycle[0]),
                    );
                }
            }
        }
    }

    /**
     * @param array<string, \HybridTM\DSL\TrustBoundary> $boundaries
     * @param list<string> $path current DFS stack, root to current node
     * @param array<string, bool> $globallyVisited nodes already fully explored across all DFS starts
     * @return list<string>|null the cycle (root..repeat) if one is reachable from here
     */
    private function findCycle(array $boundaries, string $current, array $path, array &$globallyVisited): ?array
    {
        $start = array_search($current, $path, true);
        if ($start !== false) {
            return [...array_slice($path, $start), $current];
        }

        if (isset($globallyVisited[$current]) || !isset($boundaries[$current])) {
            return null;
        }

        $path[] = $current;
        foreach ($boundaries[$current]->trustBoundariesNested as $childId) {
            $cycle = $this->findCycle($boundaries, $childId, $path, $globallyVisited);
            if ($cycle !== null) {
                return $cycle;
            }
        }

        $globallyVisited[$current] = true;
        return null;
    }
}
