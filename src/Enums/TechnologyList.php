<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/**
 * An ordered, de-duplicated list of technologies for a `TechnicalAsset`
 * (ADR-10). Threagile 1.x moved from a single `Technology` enum case to a
 * list — "Nginx" is simultaneously `reverse-proxy`, `web-server` and
 * `load-balancer`, and the old single-value field forces picking one.
 *
 * Accepts both known `Technology` enum cases and arbitrary KB-defined
 * strings, since the closed enum can't anticipate every component a
 * Knowledge Base package might describe.
 *
 * @implements \IteratorAggregate<int, Technology|string>
 */
final class TechnologyList implements \IteratorAggregate, \Countable
{
    /** @var list<Technology|string> */
    private array $technologies;

    /**
     * @param array<Technology|string> $technologies
     */
    public function __construct(array $technologies = [])
    {
        $this->technologies = [];
        foreach ($technologies as $technology) {
            $this->add($technology);
        }
    }

    public function add(Technology|string $technology): static
    {
        if (!$this->contains($technology)) {
            $this->technologies[] = $technology;
        }
        return $this;
    }

    /** @return list<string> */
    public function values(): array
    {
        return array_map(
            static fn (Technology|string $t): string => $t instanceof Technology ? $t->value : $t,
            $this->technologies,
        );
    }

    /**
     * The single representative technology, for callers still on the
     * old singular `TechnicalAsset::$technology` field. The first known
     * `Technology` case wins; if the list holds only custom KB strings,
     * falls back to `Technology::Unknown` rather than guessing a mapping —
     * that degradation belongs to the KB layer, not here.
     */
    public function primary(): Technology
    {
        foreach ($this->technologies as $technology) {
            if ($technology instanceof Technology) {
                return $technology;
            }
        }
        return Technology::Unknown;
    }

    public function contains(Technology|string $technology): bool
    {
        $value = $technology instanceof Technology ? $technology->value : $technology;
        foreach ($this->technologies as $existing) {
            $existingValue = $existing instanceof Technology ? $existing->value : $existing;
            if ($existingValue === $value) {
                return true;
            }
        }
        return false;
    }

    public function count(): int
    {
        return count($this->technologies);
    }

    /** @return \ArrayIterator<int, Technology|string> */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->technologies);
    }
}
