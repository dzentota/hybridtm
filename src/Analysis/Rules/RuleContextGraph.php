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

    /** Ordinal ranking of `TechnicalAsset::properties['privilege_level']` values, low to high. */
    private const PRIVILEGE_ORDER = ['none' => 0, 'user' => 1, 'admin' => 2, 'system' => 3];

    /**
     * Ordinal ranking of `Authentication` values a threat actor must meet to
     * cross a link, low to high. `externalized-via-gateway` is always
     * crossable here: it delegates the auth decision to a gateway component
     * elsewhere in the model, not to the caller's own credentials.
     */
    private const AUTH_ORDER = [
        'none' => 0,
        'externalized-via-gateway' => 0,
        'credentials' => 1,
        'session-id' => 1,
        'token' => 1,
        'client-certificate' => 2,
        'two-factor' => 2,
    ];

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

    /**
     * All simple paths of at most `maxHops` edges from any threat-actor
     * asset (trait `threat_actor`) to `$target`, pruning any edge whose
     * `authentication` requirement the originating actor's declared
     * `privilege_level` property can't meet — a script-kiddie-grade
     * anonymous actor doesn't get credit for reaching through a
     * client-certificate-gated link the way an admin-privileged insider does.
     *
     * @return list<GraphPath>
     */
    public function pathsFromThreatActors(TechnicalAsset $target, int $maxHops): array
    {
        $paths = [];

        foreach ($this->model->getTechnicalAssets() as $sourceId => $source) {
            if (!$source->hasTrait('threat_actor')) {
                continue;
            }

            $privilege = self::PRIVILEGE_ORDER[$source->properties->string('privilege_level', 'none')] ?? 0;
            $this->dfsFromActor($sourceId, $sourceId, $privilege, $target->id, $maxHops, [$sourceId], $paths);
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
    private function dfsFromActor(string $actorId, string $currentId, int $privilege, string $targetId, int $hopsLeft, array $visited, array &$paths): void
    {
        if (count($paths) >= self::MAX_PATHS) {
            return;
        }

        if ($currentId === $targetId) {
            $paths[] = new GraphPath($visited, $this->model, $this->derived, $actorId);
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

            $authOrdinal = self::AUTH_ORDER[$link->link->authentication->value] ?? 0;
            if ($authOrdinal > $privilege) {
                continue; // this actor's privilege level can't satisfy the link's auth requirement
            }

            $this->dfsFromActor($actorId, $nextId, $privilege, $targetId, $hopsLeft - 1, [...$visited, $nextId], $paths);
        }
    }
}
