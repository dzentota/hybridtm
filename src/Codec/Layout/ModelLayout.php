<?php

declare(strict_types=1);

namespace HybridTM\Codec\Layout;

/**
 * Canvas layout for one model: node positions, trust-boundary group boxes,
 * manual edge routing, and viewport state (ADR-07, `threat-model.layout.json`).
 *
 * Deliberately separate from `threat-model.php` — pixel coordinates in the
 * DSL file would be reviewer noise on every mouse drag. This is a sidecar
 * a team can even `.gitignore` if it doesn't want to track layout at all.
 */
final class ModelLayout
{
    /** @param array<string, NodeLayout> $nodes assetId/runtimeId => layout
     * @param array<string, GroupLayout> $groups trustBoundaryId => layout
     * @param array<string, EdgeLayout> $edges communicationLinkId => layout
     */
    public function __construct(
        public array $nodes = [],
        public array $groups = [],
        public array $edges = [],
        public Viewport $viewport = new Viewport(),
    ) {
    }
}
