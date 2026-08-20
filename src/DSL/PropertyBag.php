<?php

declare(strict_types=1);

namespace HybridTM\DSL;

/**
 * Arbitrary component-defined data attached to a DSL entity (§3.2).
 *
 * Keys and value shapes are defined by the KB component's property schema,
 * not by this class — `set()` only enforces that values stay JSON-safe
 * (scalar or a flat array of scalars) so the bag can round-trip through the
 * canonical JSON model without surprises. It is deliberately absent from
 * `ThreagileSerializer`: Threagile has no concept of custom properties.
 */
final class PropertyBag implements \JsonSerializable, \Countable
{
    /** @var array<string, bool|int|float|string|array<int, bool|int|float|string>> */
    private array $values = [];

    /**
     * @param array<string, mixed> $values
     */
    public function __construct(array $values = [])
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value);
        }
    }

    public function set(string $key, mixed $value): static
    {
        $this->values[$key] = $this->assertValidValue($key, $value);
        return $this;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    public function bool(string $key, bool $default = false): bool
    {
        $value = $this->get($key);
        return is_bool($value) ? $value : $default;
    }

    public function string(string $key, string $default = ''): string
    {
        $value = $this->get($key);
        return is_scalar($value) ? (string) $value : $default;
    }

    public function int(string $key, int $default = 0): int
    {
        $value = $this->get($key);
        return is_int($value) ? $value : (is_numeric($value) ? (int) $value : $default);
    }

    public function count(): int
    {
        return count($this->values);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->values;
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->values;
    }

    private function assertValidValue(string $key, mixed $value): mixed
    {
        if (is_scalar($value)) {
            return $value;
        }

        if (is_array($value)) {
            foreach ($value as $item) {
                if (!is_scalar($item)) {
                    throw new \InvalidArgumentException(
                        "Property \"{$key}\": array values must be scalar, got " . get_debug_type($item),
                    );
                }
            }
            return $value;
        }

        throw new \InvalidArgumentException(
            "Property \"{$key}\": value must be scalar or an array of scalars, got " . get_debug_type($value),
        );
    }
}
