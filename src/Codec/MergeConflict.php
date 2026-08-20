<?php

declare(strict_types=1);

namespace HybridTM\Codec;

/**
 * One field where `ours` and `theirs` disagree in a way `ModelMerger`
 * couldn't resolve automatically (§6.4, T-4.9): both sides changed the
 * same field to different values, or one side deleted an entity the other
 * modified.
 */
final readonly class MergeConflict
{
    public function __construct(
        public string $path,
        public mixed $base,
        public mixed $ours,
        public mixed $theirs,
    ) {
    }

    public function __toString(): string
    {
        return sprintf(
            '%s: base=%s ours=%s theirs=%s',
            $this->path,
            json_encode($this->base),
            json_encode($this->ours),
            json_encode($this->theirs),
        );
    }
}
