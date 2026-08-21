<?php

declare(strict_types=1);

namespace HybridTM\Codec;

use HybridTM\DSL\ThreatModel;

/**
 * Renders a ThreatModel as a Graphviz DOT graph (T-10.4) — `dot -Tsvg` (or
 * any Graphviz frontend) turns this straight into a diagram. Trust
 * boundaries become `cluster_*` subgraphs, which Graphviz draws as a
 * bordered box around their contained nodes — the same visual convention
 * Threagile's own DOT output uses, so this should look familiar next to
 * it.
 */
final class GraphvizExporter
{
    public function export(ThreatModel $model): string
    {
        $lines = ['digraph HybridTM {', '    rankdir=LR;', '    node [shape=box];'];

        $assetToBoundary = [];
        foreach ($model->getTrustBoundaries() as $boundaryId => $boundary) {
            foreach ($boundary->technicalAssetsInside as $assetId) {
                $assetToBoundary[$assetId] = $boundaryId;
            }
        }

        foreach ($model->getTrustBoundaries() as $boundaryId => $boundary) {
            $lines[] = "    subgraph \"cluster_{$this->id($boundaryId)}\" {";
            $lines[] = "        label=\"{$this->escape($boundary->name)}\";";
            foreach ($boundary->technicalAssetsInside as $assetId) {
                $asset = $model->getTechnicalAsset($assetId);
                if ($asset !== null) {
                    $lines[] = "        \"{$this->id($assetId)}\" [label=\"{$this->escape($asset->name)}\"];";
                }
            }
            $lines[] = '    }';
        }

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            if (!isset($assetToBoundary[$assetId])) {
                $lines[] = "    \"{$this->id($assetId)}\" [label=\"{$this->escape($asset->name)}\"];";
            }
        }

        foreach ($model->getTechnicalAssets() as $sourceId => $asset) {
            foreach ($asset->communicationLinks as $link) {
                $label = $this->escape($link->protocol->value);
                $lines[] = "    \"{$this->id($sourceId)}\" -> \"{$this->id($link->targetAssetId)}\" [label=\"{$label}\"];";
            }
        }

        $lines[] = '}';

        return implode("\n", $lines) . "\n";
    }

    private function id(string $id): string
    {
        return preg_replace('/[^A-Za-z0-9_]/', '_', $id) ?? $id;
    }

    private function escape(string $text): string
    {
        return str_replace('"', '\\"', $text);
    }
}
