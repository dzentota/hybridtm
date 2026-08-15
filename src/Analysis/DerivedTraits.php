<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

/**
 * Output of the engine's Derive phase (§5.2 phase 3): trait names the
 * engine computed itself, per technical asset id, as opposed to traits a
 * KB component declared directly (`TechnicalAsset::$traits`). Subjects
 * union both sets when answering `hasTrait()`.
 */
final class DerivedTraits
{
    /** @var array<string, list<string>> */
    private array $traits = [];

    public function add(string $assetId, string $trait): void
    {
        if (!in_array($trait, $this->traits[$assetId] ?? [], true)) {
            $this->traits[$assetId][] = $trait;
        }
    }

    /** @return list<string> */
    public function forAsset(string $assetId): array
    {
        return $this->traits[$assetId] ?? [];
    }
}
