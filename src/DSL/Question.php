<?php
declare(strict_types=1);
namespace HybridTM\DSL;

/** A governance question posed to the modeled system, e.g. "Was a pentest performed?" (§3.1). */
class Question
{
    public function __construct(
        public readonly string $id,
        public string $text,
        public ?string $answer = null,
    ) {
    }
}
