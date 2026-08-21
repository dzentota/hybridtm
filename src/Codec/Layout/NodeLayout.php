<?php

declare(strict_types=1);

namespace HybridTM\Codec\Layout;

/** Canvas position and size of one node (component or shared runtime), ADR-07. */
final readonly class NodeLayout
{
    public function __construct(
        public float $x,
        public float $y,
        public float $w = 220.0,
        public float $h = 96.0,
    ) {
    }

    /** @return array{x: float, y: float, w: float, h: float} */
    public function toArray(): array
    {
        return ['x' => $this->x, 'y' => $this->y, 'w' => $this->w, 'h' => $this->h];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            (float) ($data['x'] ?? 0),
            (float) ($data['y'] ?? 0),
            (float) ($data['w'] ?? 220),
            (float) ($data['h'] ?? 96),
        );
    }
}
