<?php
declare(strict_types=1);
namespace HybridTM\Analysis\Subjects;

use HybridTM\Enums\Protocol;

/**
 * Exposes `flow.protocol.isEncrypted()`. For string comparisons use
 * `flow.protocol.value == 'https'`, not `flow.protocol == 'https'` — PHP's
 * `==` does not invoke `__toString()` when comparing an object to a string,
 * so the bare-object form would silently always be false.
 */
final readonly class ProtocolSubject
{
    public string $value;

    public function __construct(private Protocol $protocol)
    {
        $this->value = $protocol->value;
    }

    public function isEncrypted(): bool
    {
        return $this->protocol->isEncrypted();
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
