<?php
declare(strict_types=1);
namespace HybridTM\Attributes;

use Attribute;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Protocol;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION | Attribute::IS_REPEATABLE)]
final class DataFlow
{
    /**
     * @param string         $target         ID of the target TechnicalAsset in the DSL
     * @param Protocol       $protocol       Communication protocol
     * @param Authentication $authentication Authentication mechanism
     * @param Authorization  $authorization  Authorization mechanism
     * @param string[]       $dataSent       IDs of DataAssets sent
     * @param string[]       $dataReceived   IDs of DataAssets received
     * @param bool           $vpn            Whether VPN is used
     * @param bool           $ipFiltered     Whether IP filtering is applied
     * @param bool           $readonly       Whether this is a read-only link
     */
    public function __construct(
        public readonly string $target,
        public readonly Protocol $protocol = Protocol::Https,
        public readonly Authentication $authentication = Authentication::None,
        public readonly Authorization $authorization = Authorization::None,
        public readonly array $dataSent = [],
        public readonly array $dataReceived = [],
        public readonly bool $vpn = false,
        public readonly bool $ipFiltered = false,
        public readonly bool $readonly = false,
    ) {}
}
