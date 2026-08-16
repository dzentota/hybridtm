<?php
declare(strict_types=1);
namespace HybridTM\Codec;

use HybridTM\Codec\Layout\EdgeLayout;
use HybridTM\Codec\Layout\GroupLayout;
use HybridTM\Codec\Layout\ModelLayout;
use HybridTM\Codec\Layout\NodeLayout;
use HybridTM\Codec\Layout\Viewport;
use HybridTM\DSL\ThreatModel;

/**
 * Encodes/decodes the `threat-model.layout.json` sidecar (ADR-07, T-4.7)
 * and generates a default layout when one doesn't exist yet.
 *
 * The default layout is a deterministic grid — good enough that a model
 * is never dumped on an empty canvas with everything stacked at (0,0),
 * not a real force-directed/hierarchical layout. Studio's real auto-layout
 * (ELK.js, T-7.14) runs client-side in a web worker; porting ELK to PHP
 * isn't this codec's job, and a JSON layout file has no way to invoke it
 * anyway.
 */
final class LayoutCodec
{
    private const SCHEMA_VERSION = 1;
    private const COLUMNS = 4;
    private const NODE_W = 220.0;
    private const NODE_H = 96.0;
    private const GAP_X = 60.0;
    private const GAP_Y = 60.0;
    private const GROUP_PADDING = 40.0;

    /** @return array<string, mixed> */
    public function encode(ModelLayout $layout): array
    {
        return [
            'schemaVersion' => self::SCHEMA_VERSION,
            'nodes' => array_map(static fn (NodeLayout $n): array => $n->toArray(), $layout->nodes),
            'groups' => array_map(static fn (GroupLayout $g): array => $g->toArray(), $layout->groups),
            'edges' => array_map(static fn (EdgeLayout $e): array => $e->toArray(), $layout->edges),
            'viewport' => $layout->viewport->toArray(),
        ];
    }

    /** @param array<string, mixed> $data */
    public function decode(array $data): ModelLayout
    {
        return new ModelLayout(
            nodes: array_map(
                static fn ($n): NodeLayout => NodeLayout::fromArray((array) $n),
                (array) ($data['nodes'] ?? []),
            ),
            groups: array_map(
                static fn ($g): GroupLayout => GroupLayout::fromArray((array) $g),
                (array) ($data['groups'] ?? []),
            ),
            edges: array_map(
                static fn ($e): EdgeLayout => EdgeLayout::fromArray((array) $e),
                (array) ($data['edges'] ?? []),
            ),
            viewport: Viewport::fromArray((array) ($data['viewport'] ?? [])),
        );
    }

    /**
     * Reads `$path` if it exists and is valid JSON; otherwise generates a
     * default grid layout for `$model`. A missing or unreadable sidecar
     * never blocks loading the model itself (T-4.7 DoD).
     */
    public function loadOrGenerate(string $path, ThreatModel $model): ModelLayout
    {
        if (is_file($path)) {
            $contents = file_get_contents($path);
            if ($contents !== false) {
                $data = json_decode($contents, true);
                if (is_array($data)) {
                    return $this->decode($data);
                }
            }
        }

        return $this->generateDefault($model);
    }

    public function generateDefault(ThreatModel $model): ModelLayout
    {
        $nodes = [];
        $index = 0;
        foreach (array_keys($model->getTechnicalAssets()) as $id) {
            $column = $index % self::COLUMNS;
            $row = intdiv($index, self::COLUMNS);
            $nodes[$id] = new NodeLayout(
                x: $column * (self::NODE_W + self::GAP_X),
                y: $row * (self::NODE_H + self::GAP_Y),
                w: self::NODE_W,
                h: self::NODE_H,
            );
            ++$index;
        }

        $groups = [];
        foreach ($model->getTrustBoundaries() as $id => $boundary) {
            $memberNodes = array_intersect_key($nodes, array_flip($boundary->technicalAssetsInside));
            if ($memberNodes === []) {
                continue;
            }
            $groups[$id] = $this->boundingBox($memberNodes);
        }

        return new ModelLayout($nodes, $groups, [], new Viewport());
    }

    /** @param array<string, NodeLayout> $nodes */
    private function boundingBox(array $nodes): GroupLayout
    {
        $minX = min(array_map(static fn (NodeLayout $n): float => $n->x, $nodes));
        $minY = min(array_map(static fn (NodeLayout $n): float => $n->y, $nodes));
        $maxX = max(array_map(static fn (NodeLayout $n): float => $n->x + $n->w, $nodes));
        $maxY = max(array_map(static fn (NodeLayout $n): float => $n->y + $n->h, $nodes));

        return new GroupLayout(
            x: $minX - self::GROUP_PADDING,
            y: $minY - self::GROUP_PADDING,
            w: ($maxX - $minX) + 2 * self::GROUP_PADDING,
            h: ($maxY - $minY) + 2 * self::GROUP_PADDING,
        );
    }
}
