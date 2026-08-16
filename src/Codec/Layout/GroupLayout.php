<?php
declare(strict_types=1);
namespace HybridTM\Codec\Layout;

/** Canvas bounding box of a trust boundary, drawn as a group on the canvas (ADR-07). */
final readonly class GroupLayout
{
    public function __construct(
        public float $x,
        public float $y,
        public float $w,
        public float $h,
        public bool $collapsed = false,
    ) {
    }

    /** @return array{x: float, y: float, w: float, h: float, collapsed: bool} */
    public function toArray(): array
    {
        return ['x' => $this->x, 'y' => $this->y, 'w' => $this->w, 'h' => $this->h, 'collapsed' => $this->collapsed];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            (float) ($data['x'] ?? 0),
            (float) ($data['y'] ?? 0),
            (float) ($data['w'] ?? 0),
            (float) ($data['h'] ?? 0),
            (bool) ($data['collapsed'] ?? false),
        );
    }
}
