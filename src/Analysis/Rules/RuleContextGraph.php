<?php
declare(strict_types=1);
namespace HybridTM\Analysis\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\ModelIndex;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;

/** `$ctx->graph` — topology queries for PHP rule implementations (§4.6 level 3). */
final readonly class RuleContextGraph
{
    /** Hard cap on enumerated paths per call, guarding against combinatorial blow-up on dense graphs. */
    private const MAX_PATHS = 200;

    public function __construct(
        private ThreatModel $model,
        private ModelIndex $index,
        private DerivedTraits $derived,
    ) {
    }

    /**
     * All simple paths (no repeated node) of at most `maxHops` edges from
     * any internet-facing asset to `$target`, forward along communication
     * links. `$target` itself being internet-facing yields a trivial
     * single-node path.
     *
     * @return list<GraphPath>
     */
    public function pathsFromInternet(TechnicalAsset $target, int $maxHops): array
    {
        $paths = [];

        foreach ($this->model->getTechnicalAssets() as $sourceId => $source) {
            if (!$source->internet) {
                continue;
            }
            $this->dfs($sourceId, $target->id, $maxHops, [$sourceId], $paths);
            if (count($paths) >= self::MAX_PATHS) {
                break;
            }
        }

        return $paths;
    }

    /**
     * @param list<string> $visited current path, source to here
     * @param list<GraphPath> $paths accumulated by reference
     */
    private function dfs(string $currentId, string $targetId, int $hopsLeft, array $visited, array &$paths): void
    {
        if (count($paths) >= self::MAX_PATHS) {
            return;
        }

        if ($currentId === $targetId) {
            $paths[] = new GraphPath($visited, $this->model, $this->derived);
            return;
        }

        if ($hopsLeft <= 0) {
            return;
        }

        foreach ($this->index->outgoingLinks($currentId) as $link) {
            $nextId = $link->targetAssetId;
            if (in_array($nextId, $visited, true)) {
                continue; // no cycles within one simple path
            }
            $this->dfs($nextId, $targetId, $hopsLeft - 1, [...$visited, $nextId], $paths);
        }
    }
}
