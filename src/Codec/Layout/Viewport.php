<?php
declare(strict_types=1);
namespace HybridTM\Codec\Layout;

/** Canvas pan/zoom state, ADR-07. */
final readonly class Viewport
{
    public function __construct(
        public float $x = 0.0,
        public float $y = 0.0,
        public float $zoom = 1.0,
    ) {
    }

    /** @return array{x: float, y: float, zoom: float} */
    public function toArray(): array
    {
        return ['x' => $this->x, 'y' => $this->y, 'zoom' => $this->zoom];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            (float) ($data['x'] ?? 0),
            (float) ($data['y'] ?? 0),
            (float) ($data['zoom'] ?? 1),
        );
    }
}
