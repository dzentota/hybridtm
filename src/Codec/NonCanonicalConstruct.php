<?php
declare(strict_types=1);
namespace HybridTM\Codec;

/** One construct `PhpDslReader` couldn't recognize (ADR-08). */
final readonly class NonCanonicalConstruct
{
    public function __construct(
        public int $line,
        public string $description,
    ) {
    }

    public function __toString(): string
    {
        return "line {$this->line}: {$this->description}";
    }
}
