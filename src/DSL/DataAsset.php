<?php
declare(strict_types=1);
namespace HybridTM\DSL;

use HybridTM\Enums\Availability;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Quantity;

class DataAsset
{
    public string $description = '';
    public DataUsage $usage = DataUsage::Business;
    public DataOrigin $origin = DataOrigin::Unknown;
    public string $owner = '';
    public Quantity $quantity = Quantity::Many;
    public Confidentiality $confidentiality = Confidentiality::Internal;
    public Integrity $integrity = Integrity::Operational;
    public Availability $availability = Availability::Operational;
    public string $justificationCiaRating = '';
    /** @var string[] */
    public array $tags = [];

    public function __construct(public readonly string $id, public string $name = '') {
        if ($this->name === '') $this->name = $this->id;
    }
}
