<?php

declare(strict_types=1);

namespace HybridTM\Attributes;

#[\Attribute(\Attribute::TARGET_CLASS)]
final class AssetId
{
    public function __construct(public readonly string $id)
    {
    }
}
