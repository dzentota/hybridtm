<?php
declare(strict_types=1);
namespace HybridTM\Compiler;

use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Protocol;

final class DiscoveredDataFlow
{
    public function __construct(
        public readonly string $sourceAssetId,
        public readonly string $targetAssetId,
        public readonly Protocol $protocol,
        public readonly Authentication $authentication,
        public readonly Authorization $authorization,
        public readonly array $dataSent,
        public readonly array $dataReceived,
        public readonly bool $vpn,
        public readonly bool $ipFiltered,
        public readonly bool $readonly,
        public readonly string $context,
    ) {}
}
