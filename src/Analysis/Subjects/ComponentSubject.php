<?php
declare(strict_types=1);
namespace HybridTM\Analysis\Subjects;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\DSL\PropertyBag;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Confidentiality;

/**
 * The `component` variable exposed to component-scope rule expressions
 * (§4.6). Only ever carries safe, deterministic read accessors — this
 * class's public surface *is* the expression sandbox's whitelist (ADR-05):
 * nothing dangerous is reachable because nothing dangerous is exposed,
 * not because of a runtime interceptor.
 */
final readonly class ComponentSubject
{
    public string $id;
    public string $name;
    public string $encryption;
    public bool $internet;
    public bool $redundant;
    public bool $multiTenant;
    public bool $customDevelopedParts;
    public bool $outOfScope;
    public PropertyBag $props;

    public function __construct(
        private TechnicalAsset $asset,
        private ThreatModel $model,
        private DerivedTraits $derived,
    ) {
        $this->id = $asset->id;
        $this->name = $asset->name;
        $this->encryption = $asset->encryption->value;
        $this->internet = $asset->internet;
        $this->redundant = $asset->redundant;
        $this->multiTenant = $asset->multiTenant;
        $this->customDevelopedParts = $asset->customDevelopedParts;
        $this->outOfScope = $asset->outOfScope;
        $this->props = $asset->properties;
    }

    /** OR semantics: true if the asset declares or derives any of the given traits. */
    public function hasTrait(string ...$traits): bool
    {
        foreach ($traits as $trait) {
            if ($this->asset->hasTrait($trait) || in_array($trait, $this->derived->forAsset($this->id), true)) {
                return true;
            }
        }
        return false;
    }

    public function hasAllTraits(string ...$traits): bool
    {
        foreach ($traits as $trait) {
            if (!$this->hasTrait($trait)) {
                return false;
            }
        }
        return true;
    }

    /** True if any data asset this component processes or stores meets the confidentiality threshold. */
    public function storesConfidentialityAtLeast(string $level): bool
    {
        $threshold = Confidentiality::from($level);
        foreach ([...$this->asset->dataAssetsProcessed, ...$this->asset->dataAssetsStored] as $dataId) {
            $confidentiality = $this->model->getDataAsset($dataId)?->confidentiality;
            if ($confidentiality !== null && $confidentiality->isAtLeast($threshold)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Always false in this engine version: whether a #[Mitigation] closes a
     * CWE requires the AST scanner's DiscoveredMitigation list, which
     * AnalyzerInterface::analyze() has no parameter for yet. Present so KB
     * rule authors can write `hasMitigationFor(...)` in `unless` today
     * without a runtime error; it will start suppressing once that wiring
     * lands (tracked as a follow-up, not silently done here).
     */
    public function hasMitigationFor(string $cwe): bool
    {
        return false;
    }
}
