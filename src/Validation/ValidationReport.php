<?php

declare(strict_types=1);

namespace HybridTM\Validation;

use HybridTM\Enums\ValidationSeverity;

/**
 * Collects every problem instead of throwing on the first one.
 * The editor needs the full list to render inline markers; the CLI
 * needs it to print a useful report rather than one line at a time.
 */
final class ValidationReport implements \JsonSerializable, \Countable
{
    /** @var list<ValidationIssue> */
    private array $issues = [];

    /** @param list<ValidationIssue> $issues */
    public function __construct(array $issues = [])
    {
        foreach ($issues as $issue) {
            $this->add($issue);
        }
    }

    public function add(ValidationIssue $issue): static
    {
        $this->issues[] = $issue;

        return $this;
    }

    public function merge(self $other): static
    {
        foreach ($other->issues as $issue) {
            $this->add($issue);
        }

        return $this;
    }

    /** @return list<ValidationIssue> */
    public function all(): array
    {
        return $this->issues;
    }

    /** @return list<ValidationIssue> */
    public function bySeverity(ValidationSeverity $severity): array
    {
        return array_values(array_filter(
            $this->issues,
            static fn (ValidationIssue $i): bool => $i->severity === $severity,
        ));
    }

    public function hasErrors(): bool
    {
        return $this->bySeverity(ValidationSeverity::Error) !== [];
    }

    public function count(): int
    {
        return count($this->issues);
    }

    /** @return array{issues: list<ValidationIssue>, hasErrors: bool, counts: array<string, int>} */
    public function jsonSerialize(): array
    {
        $counts = [];
        foreach (ValidationSeverity::cases() as $severity) {
            $counts[$severity->value] = count($this->bySeverity($severity));
        }

        return [
            'issues' => $this->issues,
            'hasErrors' => $this->hasErrors(),
            'counts' => $counts,
        ];
    }
}
