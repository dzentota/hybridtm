<?php
declare(strict_types=1);
namespace HybridTM\Codec;

/**
 * Deterministically maps entity ids to PHP variable names for
 * `PhpDslWriter`: camelCase of the kebab-case id, with a numeric suffix on
 * collision (e.g. two entities of different kinds sharing an id) so every
 * generated variable name is unique within one file.
 */
final class VariableNamer
{
    /** @var array<string, int> variable name => next suffix to try */
    private array $seen = [];

    public function for(string $id): string
    {
        $base = lcfirst(str_replace(' ', '', ucwords(str_replace(['-', '_'], ' ', $id))));
        if ($base === '') {
            $base = 'entity';
        }

        if (!isset($this->seen[$base])) {
            $this->seen[$base] = 2;
            return $base;
        }

        $candidate = $base . $this->seen[$base];
        $this->seen[$base]++;
        return $candidate;
    }
}
