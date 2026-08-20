<?php

declare(strict_types=1);

namespace HybridTM\Codec;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Technology;

/**
 * Import/export for the Open Threat Model format (T-4.8, ADR-13) —
 * IriusRisk's open JSON interchange format, also produced by IaC scanners
 * like `startleft`. This is the enterprise-buyer "can we leave / integrate
 * with what we already have" answer, and a free import channel for
 * existing infrastructure via startleft's Terraform/CloudFormation output.
 *
 * Scoped to structure, not risk content: `components`, `trustZones` (with
 * `parent` containment) and `dataflows` round-trip; `threats` and
 * `mitigations` are read-only passed through on import counts but never
 * constructed on export — OTM's threat/mitigation shape and HybridTM's own
 * `Finding`/`Threat` KB entities are different enough concepts (a KB-backed
 * rule engine vs. a flat per-model list) that mapping between them is a
 * distinct, separately-scoped follow-up, not a gap in this class. OTM's
 * top-level `assets` array (data assets) is likewise not mapped: the
 * fetched OTM schema fragment this codec was built against didn't specify
 * its item shape precisely enough to guess at safely.
 *
 * OTM has no protocol/authentication/authorization vocabulary — every
 * imported dataflow becomes an HTTPS link with no auth, which is honestly
 * wrong for many flows; treat an OTM import as a topology starting point
 * to review, not a finished model.
 */
final class OtmCodec
{
    private const OTM_VERSION = '0.2.0';
    private const DEFAULT_TRUST_ZONE_ID = 'default';

    /** @return array<string, mixed> */
    public function export(ThreatModel $model): array
    {
        $childToParentBoundary = $this->invertNesting($model);

        $trustZones = [];
        foreach ($model->getTrustBoundaries() as $id => $boundary) {
            $trustZones[] = array_filter([
                'id' => $id,
                'name' => $boundary->name,
                'description' => $boundary->description,
                'risk' => ['trustRating' => 50],
                'parent' => isset($childToParentBoundary[$id]) ? ['trustZone' => $childToParentBoundary[$id]] : null,
            ], static fn ($v): bool => $v !== null && $v !== '');
        }
        $trustZones[] = ['id' => self::DEFAULT_TRUST_ZONE_ID, 'name' => 'Default', 'risk' => ['trustRating' => 50]];

        $boundaryOfAsset = [];
        foreach ($model->getTrustBoundaries() as $id => $boundary) {
            foreach ($boundary->technicalAssetsInside as $assetId) {
                $boundaryOfAsset[$assetId] = $id;
            }
        }

        $components = [];
        $dataflows = [];
        foreach ($model->getTechnicalAssets() as $id => $asset) {
            $components[] = array_filter([
                'id' => $id,
                'name' => $asset->name,
                'type' => $asset->technology->value,
                'description' => $asset->description,
                'parent' => ['trustZone' => $boundaryOfAsset[$id] ?? self::DEFAULT_TRUST_ZONE_ID],
                'tags' => $asset->tags,
            ], static fn ($v): bool => $v !== '' && $v !== []);

            foreach ($asset->communicationLinks as $link) {
                $dataflows[] = array_filter([
                    'id' => $link->id,
                    'name' => $link->description !== '' ? $link->description : $link->id,
                    'source' => $id,
                    'destination' => $link->targetAssetId,
                    'bidirectional' => false,
                    'tags' => $link->tags,
                ], static fn ($v): bool => $v !== '' && $v !== []);
            }
        }

        return [
            'otmVersion' => self::OTM_VERSION,
            'project' => array_filter([
                'id' => $this->slug($model->title),
                'name' => $model->title,
                'description' => $model->description,
            ], static fn ($v): bool => $v !== ''),
            'trustZones' => $trustZones,
            'components' => $components,
            'dataflows' => $dataflows,
        ];
    }

    /** @param array<string, mixed> $otm */
    public function import(array $otm): ThreatModel
    {
        $project = (array) ($otm['project'] ?? []);
        $model = new ThreatModel((string) ($project['name'] ?? 'Imported OTM Model'));
        $model->description = (string) ($project['description'] ?? '');

        $zoneParents = [];
        foreach ((array) ($otm['trustZones'] ?? []) as $zone) {
            $zone = (array) $zone;
            $id = (string) $zone['id'];
            if ($id === self::DEFAULT_TRUST_ZONE_ID) {
                continue; // our own export-side synthetic fallback zone
            }

            $model->addTrustBoundary(new TrustBoundary($id, (string) ($zone['name'] ?? $id)));
            $model->getTrustBoundaries()[$id]->description = (string) ($zone['description'] ?? '');

            $parentZone = $zone['parent']['trustZone'] ?? null;
            if (is_string($parentZone) && $parentZone !== self::DEFAULT_TRUST_ZONE_ID) {
                $zoneParents[$id] = $parentZone;
            }
        }
        foreach ($zoneParents as $childId => $parentId) {
            $parent = $model->getTrustBoundaries()[$parentId] ?? null;
            if ($parent !== null && !in_array($childId, $parent->trustBoundariesNested, true)) {
                $parent->trustBoundariesNested[] = $childId;
            }
        }

        $assetZone = [];
        foreach ((array) ($otm['components'] ?? []) as $component) {
            $component = (array) $component;
            $id = (string) $component['id'];

            $asset = new TechnicalAsset($id, (string) ($component['name'] ?? $id));
            $asset->description = (string) ($component['description'] ?? '');
            $asset->technology = Technology::tryFrom((string) ($component['type'] ?? '')) ?? Technology::Unknown;
            $asset->tags = array_map(static fn ($t): string => (string) $t, (array) ($component['tags'] ?? []));
            $model->addTechnicalAsset($asset);

            $zone = $component['parent']['trustZone'] ?? null;
            if (is_string($zone) && $zone !== self::DEFAULT_TRUST_ZONE_ID) {
                $assetZone[$id] = $zone;
            }
        }
        foreach ($assetZone as $assetId => $zoneId) {
            $model->getTrustBoundaries()[$zoneId]?->addAssets($assetId);
        }

        foreach ((array) ($otm['dataflows'] ?? []) as $flow) {
            $flow = (array) $flow;
            $source = $model->getTechnicalAsset((string) ($flow['source'] ?? ''));
            if ($source === null) {
                continue;
            }
            $link = $source->communicatesTo(targetId: (string) ($flow['destination'] ?? ''));
            $link->description = (string) ($flow['name'] ?? '');
            $link->tags = array_map(static fn ($t): string => (string) $t, (array) ($flow['tags'] ?? []));
        }

        return $model;
    }

    /** @return array<string, string> childBoundaryId => parentBoundaryId */
    private function invertNesting(ThreatModel $model): array
    {
        $result = [];
        foreach ($model->getTrustBoundaries() as $parentId => $boundary) {
            foreach ($boundary->trustBoundariesNested as $childId) {
                $result[$childId] = $parentId;
            }
        }
        return $result;
    }

    private function slug(string $title): string
    {
        $slug = strtolower(trim((string) preg_replace('/[^a-z0-9]+/i', '-', $title), '-'));
        return $slug !== '' ? $slug : 'model';
    }
}
