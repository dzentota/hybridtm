<?php
declare(strict_types=1);
namespace HybridTM\DSL;

use HybridTM\Enums\AssetType;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Availability;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Size;
use HybridTM\Enums\Technology;

class TechnicalAsset
{
    public string $description = '';
    public AssetType $type = AssetType::Process;
    public DataUsage $usage = DataUsage::Business;
    public bool $usedAsClientByHuman = false;
    public bool $outOfScope = false;
    public string $justificationOutOfScope = '';
    public Size $size = Size::Service;
    public Technology $technology = Technology::WebServiceRest;
    public bool $internet = false;
    public Machine $machine = Machine::Virtual;
    public Encryption $encryption = Encryption::None;
    public string $owner = '';
    public Confidentiality $confidentiality = Confidentiality::Internal;
    public Integrity $integrity = Integrity::Operational;
    public Availability $availability = Availability::Operational;
    public string $justificationCiaRating = '';
    public bool $multiTenant = false;
    public bool $redundant = false;
    public bool $customDevelopedParts = false;
    /** @var string[] IDs of DataAssets processed */
    public array $dataAssetsProcessed = [];
    /** @var string[] IDs of DataAssets stored */
    public array $dataAssetsStored = [];
    /** @var string[] */
    public array $dataFormatsAccepted = [];
    /** @var string[] */
    public array $tags = [];
    /** @var CommunicationLink[] keyed by link id */
    public array $communicationLinks = [];

    public function __construct(public readonly string $id, public string $name = '') {
        if ($this->name === '') $this->name = $this->id;
    }

    public function communicatesTo(
        string $targetId,
        Protocol $protocol = Protocol::Https,
        Authentication $authentication = Authentication::None,
        Authorization $authorization = Authorization::None,
        string $description = '',
    ): CommunicationLink {
        $linkId = $this->id . '-to-' . $targetId;
        $link = new CommunicationLink($linkId, $targetId, $protocol, $authentication, $authorization);
        $link->description = $description;
        $this->communicationLinks[$linkId] = $link;
        return $link;
    }
}
