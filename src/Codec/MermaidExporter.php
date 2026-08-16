<?php
declare(strict_types=1);
namespace HybridTM\Codec;

use HybridTM\DSL\ThreatModel;

/**
 * Renders a ThreatModel as a Mermaid flowchart (T-10.4) — the format
 * GitHub/GitLab READMEs and most wikis render natively from a fenced
 * ```mermaid``` code block, no external tool needed. Trust boundaries
 * become `subgraph`s; components outside any boundary are left at the
 * top level. Node/edge ids are the model's own asset/link ids, sanitized
 * to Mermaid's identifier rules (alphanumeric + underscore).
 */
final class MermaidExporter
{
    public function export(ThreatModel $model): string
    {
        $lines = ['flowchart LR'];

        $assetToBoundary = [];
        foreach ($model->getTrustBoundaries() as $boundaryId => $boundary) {
            foreach ($boundary->technicalAssetsInside as $assetId) {
                $assetToBoundary[$assetId] = $boundaryId;
            }
        }

        foreach ($model->getTrustBoundaries() as $boundaryId => $boundary) {
            $lines[] = "    subgraph {$this->id($boundaryId)}[\"{$this->escape($boundary->name)}\"]";
            foreach ($boundary->technicalAssetsInside as $assetId) {
                $asset = $model->getTechnicalAsset($assetId);
                if ($asset !== null) {
                    $lines[] = "        {$this->node($assetId, $asset->name)}";
                }
            }
            $lines[] = '    end';
        }

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            if (!isset($assetToBoundary[$assetId])) {
                $lines[] = "    {$this->node($assetId, $asset->name)}";
            }
        }

        foreach ($model->getTechnicalAssets() as $sourceId => $asset) {
            foreach ($asset->communicationLinks as $link) {
                $label = $link->protocol->value;
                $lines[] = "    {$this->id($sourceId)} -->|{$label}| {$this->id($link->targetAssetId)}";
            }
        }

        return implode("\n", $lines) . "\n";
    }

    private function node(string $id, string $name): string
    {
        return "{$this->id($id)}[\"{$this->escape($name)}\"]";
    }

    private function id(string $id): string
    {
        return preg_replace('/[^A-Za-z0-9_]/', '_', $id) ?? $id;
    }

    private function escape(string $text): string
    {
        return str_replace('"', "'", $text);
    }
}
