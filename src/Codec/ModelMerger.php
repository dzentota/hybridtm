<?php
declare(strict_types=1);
namespace HybridTM\Codec;

use HybridTM\DSL\ThreatModel;

/**
 * Three-way merge of two divergent edits to the same model (§6.4, T-4.9) —
 * the operation behind resolving "I edited this in Studio while a
 * colleague edited the same file in git".
 *
 * Works over the canonical JSON encoding (`ModelJsonCodec`) rather than the
 * DSL objects directly: entity collections are lists keyed by an id field,
 * which is exactly what a structural (not line-based) 3-way merge needs.
 *
 * Merge rules, applied field by field and entity by entity:
 *  - Both sides made the same change (or neither changed it): no conflict.
 *  - Only one side changed a field: take that side's value, no conflict.
 *  - Both sides changed the same field to *different* values: conflict,
 *    `ours` wins in the returned model (so the merge always produces a
 *    usable result), and the disagreement is recorded either way.
 *  - One side deleted an entity the other modified: conflict, the
 *    modification is kept (deletions never silently win over edits) and
 *    recorded.
 *  - One side deleted an entity the other left untouched: clean deletion,
 *    no conflict.
 *
 * Leaf arrays (`tags`, `dataAssetsProcessed`, ...) are merged as opaque
 * values, not element-by-element — two sides adding different tags to the
 * same asset is a conflict here, not an automatic union. That is a
 * deliberate simplification, not an oversight: union-merging every array
 * field would silently combine edits that were never meant to coexist
 * (e.g. two different `overrides.encryption` "corrections").
 */
final class ModelMerger
{
    /** @var array<string, string> top-level array field => id field to key entities by */
    private const KEYED_ARRAYS = [
        'dataAssets' => 'id',
        'components' => 'id',
        'trustBoundaries' => 'id',
        'dataFlows' => 'id',
        'sharedRuntimes' => 'id',
        'riskTracking' => 'findingStableId',
        'questions' => 'id',
        'abuseCases' => 'title',
        'securityRequirements' => 'title',
    ];

    public function __construct(private readonly ModelJsonCodec $codec = new ModelJsonCodec())
    {
    }

    public function merge3(ThreatModel $base, ThreatModel $ours, ThreatModel $theirs): MergeResult
    {
        $baseData = $this->codec->encode($base);
        $oursData = $this->codec->encode($ours);
        $theirsData = $this->codec->encode($theirs);

        $conflicts = [];
        $merged = [
            'schemaVersion' => 1,
            'model' => $this->mergeDict(
                (array) ($baseData['model'] ?? []),
                (array) ($oursData['model'] ?? []),
                (array) ($theirsData['model'] ?? []),
                'model',
                $conflicts,
            ),
        ];

        foreach (self::KEYED_ARRAYS as $field => $keyField) {
            $merged[$field] = $this->mergeKeyedList(
                (array) ($baseData[$field] ?? []),
                (array) ($oursData[$field] ?? []),
                (array) ($theirsData[$field] ?? []),
                $keyField,
                $field,
                $conflicts,
            );
        }

        $merged['kbVersion'] = $this->mergeScalar(
            $baseData['kbVersion'] ?? null,
            $oursData['kbVersion'] ?? null,
            $theirsData['kbVersion'] ?? null,
            'kbVersion',
            $conflicts,
        );
        if ($merged['kbVersion'] === null) {
            unset($merged['kbVersion']);
        }

        return new MergeResult($this->codec->decode($merged), $conflicts);
    }

    /**
     * @param array<string, mixed> $base
     * @param array<string, mixed> $ours
     * @param array<string, mixed> $theirs
     * @param list<MergeConflict> $conflicts
     * @return array<string, mixed>
     */
    private function mergeDict(array $base, array $ours, array $theirs, string $path, array &$conflicts): array
    {
        $keys = array_unique([...array_keys($base), ...array_keys($ours), ...array_keys($theirs)]);
        $result = [];

        foreach ($keys as $key) {
            $value = $this->mergeScalar($base[$key] ?? null, $ours[$key] ?? null, $theirs[$key] ?? null, "{$path}.{$key}", $conflicts);
            if ($value !== null) {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * @param list<MergeConflict> $conflicts
     */
    private function mergeScalar(mixed $base, mixed $ours, mixed $theirs, string $path, array &$conflicts): mixed
    {
        if ($ours === $theirs) {
            return $ours;
        }
        if ($ours === $base) {
            return $theirs;
        }
        if ($theirs === $base) {
            return $ours;
        }

        $conflicts[] = new MergeConflict($path, $base, $ours, $theirs);
        return $ours;
    }

    /**
     * @param list<array<string, mixed>> $base
     * @param list<array<string, mixed>> $ours
     * @param list<array<string, mixed>> $theirs
     * @param list<MergeConflict> $conflicts
     * @return list<array<string, mixed>>
     */
    private function mergeKeyedList(array $base, array $ours, array $theirs, string $keyField, string $path, array &$conflicts): array
    {
        $baseById = $this->indexBy($base, $keyField);
        $oursById = $this->indexBy($ours, $keyField);
        $theirsById = $this->indexBy($theirs, $keyField);

        $order = [...array_keys($oursById)];
        foreach (array_keys($theirsById) as $id) {
            if (!in_array($id, $order, true)) {
                $order[] = $id;
            }
        }

        $result = [];
        foreach ($order as $id) {
            $b = $baseById[$id] ?? null;
            $o = $oursById[$id] ?? null;
            $t = $theirsById[$id] ?? null;
            $entityPath = "{$path}[{$id}]";

            if ($o !== null && $t !== null) {
                $result[] = $this->mergeDict($b ?? [], $o, $t, $entityPath, $conflicts);
                continue;
            }

            if ($o !== null && $t === null) {
                // Present in ours, absent from theirs.
                if ($b === null || $o === $b) {
                    // Clean addition by ours, or theirs cleanly deleted an
                    // entity ours never touched.
                    if ($b !== null && $o === $b) {
                        continue; // clean delete by theirs
                    }
                    $result[] = $o;
                    continue;
                }
                // Ours modified an entity theirs deleted: keep the edit.
                $conflicts[] = new MergeConflict($entityPath, $b, $o, null);
                $result[] = $o;
                continue;
            }

            if ($t !== null && $o === null) {
                // Present in theirs, absent from ours (symmetric case).
                if ($b === null || $t === $b) {
                    if ($b !== null && $t === $b) {
                        continue; // clean delete by ours
                    }
                    $result[] = $t;
                    continue;
                }
                $conflicts[] = new MergeConflict($entityPath, $b, null, $t);
                $result[] = $t;
                continue;
            }

            // Absent from both ours and theirs: deleted (or never existed).
        }

        return $result;
    }

    /**
     * @param list<array<string, mixed>> $items
     * @return array<string, array<string, mixed>>
     */
    private function indexBy(array $items, string $keyField): array
    {
        $result = [];
        foreach ($items as $item) {
            if (isset($item[$keyField])) {
                $result[(string) $item[$keyField]] = $item;
            }
        }
        return $result;
    }
}
