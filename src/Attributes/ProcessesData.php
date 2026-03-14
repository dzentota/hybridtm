<?php
declare(strict_types=1);
namespace HybridTM\Attributes;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class ProcessesData
{
    /**
     * @param string[] $dataAssets IDs of DataAssets processed by this component
     */
    public function __construct(
        public readonly array $dataAssets,
    ) {}
}
