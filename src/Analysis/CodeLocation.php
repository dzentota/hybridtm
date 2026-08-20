<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

/**
 * Where in the source a fact came from. Populated by the AST scanner so a
 * finding can point at the exact method that declares the data flow, and a
 * mitigation can point at the #[Mitigation] attribute that closes it.
 */
final readonly class CodeLocation implements \JsonSerializable, \Stringable
{
    public function __construct(
        public string $file,
        public int $line,
        public ?string $class = null,
        public ?string $method = null,
    ) {
    }

    public function __toString(): string
    {
        return sprintf('%s:%d', $this->file, $this->line);
    }

    /** @return array{file: string, line: int, class: string|null, method: string|null} */
    public function jsonSerialize(): array
    {
        return [
            'file' => $this->file,
            'line' => $this->line,
            'class' => $this->class,
            'method' => $this->method,
        ];
    }
}
