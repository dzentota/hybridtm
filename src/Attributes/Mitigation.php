<?php
declare(strict_types=1);
namespace HybridTM\Attributes;

use Attribute;
use HybridTM\Enums\MitigationStatus;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS | Attribute::TARGET_FUNCTION | Attribute::IS_REPEATABLE)]
final class Mitigation
{
    public function __construct(
        public readonly string $cwe,
        public readonly string $description,
        public readonly MitigationStatus $status = MitigationStatus::Mitigated,
    ) {}
}
