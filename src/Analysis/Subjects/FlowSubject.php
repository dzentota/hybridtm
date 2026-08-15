<?php
declare(strict_types=1);
namespace HybridTM\Analysis\Subjects;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\ModelIndex;
use HybridTM\DSL\CommunicationLink;
use HybridTM\DSL\PropertyBag;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Confidentiality;

/** The `flow` variable exposed to flow-scope rule expressions (§4.6). */
final readonly class FlowSubject
{
    public string $sourceId;
    public string $targetId;
    public bool $vpn;
    public bool $ipFiltered;
    public bool $readonly;
    public ProtocolSubject $protocol;
    public PropertyBag $props;
    public ComponentSubject $source;
    public ComponentSubject $target;

    public function __construct(
        private CommunicationLink $link,
        string $sourceId,
        private ThreatModel $model,
        private ModelIndex $index,
        DerivedTraits $derived,
    ) {
        $this->sourceId = $sourceId;
        $this->targetId = $link->targetAssetId;
        $this->vpn = $link->vpn;
        $this->ipFiltered = $link->ipFiltered;
        $this->readonly = $link->readonly;
        $this->protocol = new ProtocolSubject($link->protocol);
        $this->props = $link->properties;

        $sourceAsset = $model->getTechnicalAsset($sourceId);
        $targetAsset = $model->getTechnicalAsset($this->targetId);
        $this->source = new ComponentSubject($sourceAsset, $model, $derived);
        $this->target = new ComponentSubject($targetAsset, $model, $derived);
    }

    /** True if source and target sit in different trust boundaries (including "one has none, the other does"). */
    public function crossesTrustBoundary(): bool
    {
        return $this->index->boundaryOf($this->sourceId) !== $this->index->boundaryOf($this->targetId);
    }

    /** True if any data sent or received on this link meets the confidentiality threshold. */
    public function carriesDataAtLeast(string $level): bool
    {
        $threshold = Confidentiality::from($level);
        foreach ([...$this->link->dataSent, ...$this->link->dataReceived] as $dataId) {
            $confidentiality = $this->model->getDataAsset($dataId)?->confidentiality;
            if ($confidentiality !== null && $confidentiality->isAtLeast($threshold)) {
                return true;
            }
        }
        return false;
    }
}
