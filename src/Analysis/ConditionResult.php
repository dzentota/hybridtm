<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

/**
 * One evaluated condition of a rule. Collected so the UI can answer
 * "why did this fire?" — the single most common objection to automated
 * threat modelling.
 */
final readonly class ConditionResult implements \JsonSerializable
{
    public const KIND_WHEN   = 'when';
    public const KIND_UNLESS = 'unless';

    public function __construct(
        public string $expression,
        public bool $passed,
        public string $kind = self::KIND_WHEN,
        public string $detail = '',
    ) {
    }

    /** @return array{expression: string, passed: bool, kind: string, detail: string} */
    public function jsonSerialize(): array
    {
        return [
            'expression' => $this->expression,
            'passed'     => $this->passed,
            'kind'       => $this->kind,
            'detail'     => $this->detail,
        ];
    }
}
