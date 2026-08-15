<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

/** Full evaluation record of a rule against one subject. */
final readonly class RuleTrace implements \JsonSerializable, \Countable
{
    /** @param list<ConditionResult> $conditions */
    public function __construct(
        public string $ruleId,
        public array $conditions = [],
        public bool $matched = false,
    ) {
    }

    /** @return list<ConditionResult> */
    public function failed(): array
    {
        return array_values(array_filter($this->conditions, static fn (ConditionResult $c): bool => !$c->passed));
    }

    /** Conditions that actively suppressed the finding. */
    public function suppressedBy(): array
    {
        return array_values(array_filter(
            $this->conditions,
            static fn (ConditionResult $c): bool => $c->kind === ConditionResult::KIND_UNLESS && $c->passed,
        ));
    }

    public function count(): int
    {
        return count($this->conditions);
    }

    /** @return array{ruleId: string, matched: bool, conditions: list<ConditionResult>} */
    public function jsonSerialize(): array
    {
        return [
            'ruleId'     => $this->ruleId,
            'matched'    => $this->matched,
            'conditions' => $this->conditions,
        ];
    }
}
