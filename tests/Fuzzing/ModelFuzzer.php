<?php

declare(strict_types=1);

namespace HybridTM\Tests\Fuzzing;

use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Availability;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\Size;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;

/**
 * Generates random-but-structurally-valid ThreatModels for property-based
 * testing (T-11.2) — every enum-typed field gets a genuinely random case
 * (not always the default), every boolean gets randomly flipped, and a
 * fraction of runs deliberately hit boundary values (empty tag lists,
 * zero-length/very-long strings, a model with only one asset, a model
 * with no data assets at all) rather than only "normal-looking" data.
 * Seeded so a failing run is reproducible: same seed -> same model.
 */
final class ModelFuzzer
{
    private int $seed;

    public function __construct(int $seed)
    {
        $this->seed = $seed;
        mt_srand($seed);
    }

    /** The seed this fuzzer was constructed with, for reproducing a failing run. */
    public function getSeed(): int
    {
        return $this->seed;
    }

    public function generate(): ThreatModel
    {
        $model = new ThreatModel($this->randomName('Model'));
        $model->description = $this->maybe(0.5) ? $this->randomString(0, 200) : '';

        $dataAssetCount = $this->intBetween(0, 5);
        $dataAssetIds = [];
        for ($i = 0; $i < $dataAssetCount; ++$i) {
            $dataAsset = $this->randomDataAsset("data-{$i}");
            $model->addDataAsset($dataAsset);
            $dataAssetIds[] = $dataAsset->id;
        }

        $assetCount = $this->intBetween(1, 8);
        $assetIds = [];
        for ($i = 0; $i < $assetCount; ++$i) {
            $asset = $this->randomTechnicalAsset("asset-{$i}", $dataAssetIds);
            $model->addTechnicalAsset($asset);
            $assetIds[] = $asset->id;
        }

        // Random communication links between distinct asset pairs.
        foreach ($assetIds as $sourceId) {
            if (!$this->maybe(0.6) || \count($assetIds) < 2) {
                continue;
            }
            $targetId = $assetIds[$this->intBetween(0, \count($assetIds) - 1)];
            if ($targetId === $sourceId) {
                continue;
            }
            $source = $model->getTechnicalAsset($sourceId);
            if ($source === null) {
                continue;
            }
            $link = $source->communicatesTo(
                $targetId,
                $this->randomCase(Protocol::class),
                $this->randomCase(Authentication::class),
                $this->randomCase(Authorization::class),
            );
            $link->vpn = $this->maybe(0.2);
            $link->ipFiltered = $this->maybe(0.2);
            $link->readonly = $this->maybe(0.2);
        }

        // Random trust boundaries, possibly nested.
        $boundaryCount = $this->intBetween(0, 3);
        $boundaryIds = [];
        $remainingAssets = $assetIds;
        for ($i = 0; $i < $boundaryCount && $remainingAssets !== []; ++$i) {
            $boundary = new TrustBoundary("boundary-{$i}", $this->randomName('Zone'), $this->randomCase(TrustBoundaryType::class));
            $take = $this->intBetween(1, \count($remainingAssets));
            $inside = \array_slice($remainingAssets, 0, $take);
            $boundary->addAssets(...$inside);
            $remainingAssets = \array_slice($remainingAssets, $take);
            if ($boundaryIds !== [] && $this->maybe(0.3)) {
                $boundary->trustBoundariesNested = [$boundaryIds[array_rand($boundaryIds)]];
            }
            $model->addTrustBoundary($boundary);
            $boundaryIds[] = $boundary->id;
        }

        return $model;
    }

    private function randomDataAsset(string $id): DataAsset
    {
        $asset = new DataAsset($id, $this->randomName('Data'));
        $asset->confidentiality = $this->randomCase(Confidentiality::class);
        $asset->integrity = $this->randomCase(Integrity::class);
        $asset->availability = $this->randomCase(Availability::class);
        $asset->quantity = $this->randomCase(Quantity::class);
        $asset->origin = $this->randomCase(DataOrigin::class);
        $asset->usage = $this->randomCase(DataUsage::class);
        $asset->tags = $this->maybe(0.5) ? [$this->randomString(1, 10), $this->randomString(1, 10)] : [];
        return $asset;
    }

    /** @param list<string> $dataAssetIds */
    private function randomTechnicalAsset(string $id, array $dataAssetIds): TechnicalAsset
    {
        $asset = new TechnicalAsset($id, $this->randomName('Component'));
        $asset->technology = $this->randomCase(Technology::class);
        $asset->technologies->add($asset->technology);
        $asset->machine = $this->randomCase(Machine::class);
        $asset->size = $this->randomCase(Size::class);
        $asset->encryption = $this->randomCase(Encryption::class);
        $asset->confidentiality = $this->randomCase(Confidentiality::class);
        $asset->integrity = $this->randomCase(Integrity::class);
        $asset->availability = $this->randomCase(Availability::class);
        $asset->internet = $this->maybe(0.3);
        $asset->multiTenant = $this->maybe(0.2);
        $asset->redundant = $this->maybe(0.3);
        $asset->customDevelopedParts = $this->maybe(0.3);
        $asset->outOfScope = $this->maybe(0.1);
        $asset->usedAsClientByHuman = $this->maybe(0.2);

        if ($dataAssetIds !== []) {
            $asset->dataAssetsProcessed = $this->maybe(0.4) ? [$dataAssetIds[array_rand($dataAssetIds)]] : [];
            $asset->dataAssetsStored = $this->maybe(0.4) ? [$dataAssetIds[array_rand($dataAssetIds)]] : [];
        }

        $asset->properties->set('bool_prop', $this->maybe(0.5));
        $asset->properties->set('string_prop', $this->randomString(0, 50));
        $asset->properties->set('int_prop', $this->intBetween(-1000, 1000));

        return $asset;
    }

    /** @param class-string $enumClass */
    private function randomCase(string $enumClass): mixed
    {
        $cases = $enumClass::cases();
        return $cases[$this->intBetween(0, \count($cases) - 1)];
    }

    private function randomName(string $prefix): string
    {
        return $prefix . '-' . $this->intBetween(1, 999999);
    }

    /** Occasionally hits length-0 and length-255 boundaries. */
    private function randomString(int $min, int $max): string
    {
        $roll = mt_rand(0, 99);
        $length = match (true) {
            $roll < 10 => 0,
            $roll < 20 => 255,
            default => $this->intBetween($min, $max),
        };
        $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_étü漢';
        $out = '';
        for ($i = 0; $i < $length; ++$i) {
            $out .= mb_substr($alphabet, $this->intBetween(0, mb_strlen($alphabet) - 1), 1);
        }
        return $out;
    }

    private function intBetween(int $min, int $max): int
    {
        return mt_rand($min, $max);
    }

    private function maybe(float $probability): bool
    {
        return mt_rand() / mt_getrandmax() < $probability;
    }
}
