<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\Compiler\DiscoveredMitigation;
use HybridTM\Enums\MitigationStatus;

/**
 * Index of #[Mitigation] discoveries keyed by TechnicalAsset id and CWE.
 * Built from AstScanner output and passed into analyze via AnalysisOptions.
 */
final class MitigationIndex
{
    /**
     * @param array<string, array<string, list<DiscoveredMitigation>>> $byAssetCwe
     *                                                                             assetId => cwe => mitigations
     * @param list<DiscoveredMitigation> $storyOnly mitigations without assetId but linked to an
     *                                              #[AbuserStory]; they count for story coverage only, never for asset-level KB rules
     * @param list<DiscoveredMitigation> $ignored mitigations with neither assetId nor story link
     */
    public function __construct(
        private array $byAssetCwe = [],
        private array $storyOnly = [],
        private array $ignored = [],
    ) {
    }

    /** @param list<DiscoveredMitigation> $mitigations */
    public static function fromDiscoveries(array $mitigations): self
    {
        $byAssetCwe = [];
        $storyOnly = [];
        $ignored = [];
        foreach ($mitigations as $m) {
            if ($m->cwe === '') {
                continue;
            }
            if ($m->assetId === '') {
                if ($m->abuserStoryIds !== []) {
                    $storyOnly[] = $m;
                } else {
                    $ignored[] = $m;
                }
                continue;
            }
            $byAssetCwe[$m->assetId][$m->cwe][] = $m;
        }

        return new self($byAssetCwe, $storyOnly, $ignored);
    }

    public function hasMitigated(string $assetId, string $cwe): bool
    {
        foreach ($this->byAssetCwe[$assetId][$cwe] ?? [] as $m) {
            if ($m->status === MitigationStatus::Mitigated) {
                return true;
            }
        }

        return false;
    }

    public function evidence(string $assetId, string $cwe): ?MitigationEvidence
    {
        $list = $this->byAssetCwe[$assetId][$cwe] ?? [];
        if ($list === []) {
            return null;
        }

        // Prefer Mitigated, then any other status.
        usort(
            $list,
            static fn (DiscoveredMitigation $a, DiscoveredMitigation $b): int => ($b->status === MitigationStatus::Mitigated ? 1 : 0)
                <=> ($a->status === MitigationStatus::Mitigated ? 1 : 0),
        );
        $m = $list[0];

        return new MitigationEvidence($m->cwe, $m->description, $m->status, $m->location);
    }

    /**
     * Mitigations dropped because they have neither an #[AssetId] nor a sibling #[AbuserStory].
     *
     * @return list<DiscoveredMitigation>
     */
    public function ignored(): array
    {
        return $this->ignored;
    }

    /**
     * All usable mitigations: asset-linked ones plus story-linked ones without an asset.
     *
     * @return list<DiscoveredMitigation>
     */
    public function all(): array
    {
        $out = [];
        foreach ($this->byAssetCwe as $byCwe) {
            foreach ($byCwe as $list) {
                foreach ($list as $m) {
                    $out[] = $m;
                }
            }
        }

        foreach ($this->storyOnly as $m) {
            $out[] = $m;
        }

        return $out;
    }
}
