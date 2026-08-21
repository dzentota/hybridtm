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
     *        assetId => cwe => mitigations
     */
    public function __construct(
        private array $byAssetCwe = [],
    ) {
    }

    /** @param list<DiscoveredMitigation> $mitigations */
    public static function fromDiscoveries(array $mitigations): self
    {
        $byAssetCwe = [];
        foreach ($mitigations as $m) {
            if ($m->assetId === '' || $m->cwe === '') {
                continue;
            }
            $byAssetCwe[$m->assetId][$m->cwe][] = $m;
        }

        return new self($byAssetCwe);
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

    /** @return list<DiscoveredMitigation> */
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

        return $out;
    }
}
