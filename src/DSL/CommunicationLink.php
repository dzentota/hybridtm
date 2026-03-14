<?php
declare(strict_types=1);
namespace HybridTM\DSL;

use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\Protocol;

class CommunicationLink
{
    public string $description = '';
    public DataUsage $usage = DataUsage::Business;
    public bool $vpn = false;
    public bool $ipFiltered = false;
    public bool $readonly = false;
    /** @var string[] IDs of DataAssets */
    public array $dataSent = [];
    /** @var string[] IDs of DataAssets */
    public array $dataReceived = [];
    /** @var string[] */
    public array $tags = [];

    public function __construct(
        public readonly string $id,
        public readonly string $targetAssetId,
        public Protocol $protocol = Protocol::Https,
        public Authentication $authentication = Authentication::None,
        public Authorization $authorization = Authorization::None,
    ) {}
}
