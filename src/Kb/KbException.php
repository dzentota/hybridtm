<?php

declare(strict_types=1);

namespace HybridTM\Kb;

final class KbException extends \RuntimeException
{
    public static function unknownEntity(Kind $kind, string $id): self
    {
        return new self(sprintf('Unknown %s "%s" in knowledge base.', $kind->value, $id));
    }

    public static function circularExtends(string $id, string $chain): self
    {
        return new self(sprintf('Circular "extends" chain for "%s": %s', $id, $chain));
    }

    public static function schemaViolation(string $file, string $detail): self
    {
        return new self(sprintf('Knowledge-base file "%s" is invalid: %s', $file, $detail));
    }
}
