<?php

declare(strict_types=1);

namespace HybridTM\Codec\Layout;

/**
 * Manual routing waypoints for one communication link, ADR-07. Empty
 * means "let the canvas compute a straight/orthogonal route" — most
 * edges never need this; it exists for the ones a user has manually
 * bent around something.
 */
final readonly class EdgeLayout
{
    /** @param list<array{0: float, 1: float}> $waypoints */
    public function __construct(
        public array $waypoints = [],
    ) {
    }

    /** @return list<array{0: float, 1: float}> */
    public function toArray(): array
    {
        return $this->waypoints;
    }

    /** @param list<mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(array_map(
            static fn ($point): array => [(float) $point[0], (float) $point[1]],
            $data,
        ));
    }
}
