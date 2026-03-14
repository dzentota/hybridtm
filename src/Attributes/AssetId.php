<?php
declare(strict_types=1);
namespace HybridTM\Attributes;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS)]
final class AssetId
{
    public function __construct(public readonly string $id) {}
}
