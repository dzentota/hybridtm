<?php
declare(strict_types=1);
namespace HybridTM\Codec;

use HybridTM\DSL\ThreatModel;

/** Result of `ModelMerger::merge3()`. `$model` always reflects a decision for every field. */
final readonly class MergeResult
{
    /** @param list<MergeConflict> $conflicts */
    public function __construct(
        public ThreatModel $model,
        public array $conflicts = [],
    ) {
    }

    public function hasConflicts(): bool
    {
        return $this->conflicts !== [];
    }
}
