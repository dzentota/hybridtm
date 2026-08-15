<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

use HybridTM\Enums\SubjectKind;
use InvalidArgumentException;

/**
 * Stable, serialisable pointer to whatever a finding is about.
 *
 * The string form (`component:user-db`, `flow:api->user-db`) is what feeds
 * the finding's stable id, so it must never depend on display names —
 * only on immutable ids. See ADR-11 and ADR-12.
 */
final readonly class SubjectRef implements \JsonSerializable, \Stringable
{
    private function __construct(
        public SubjectKind $kind,
        public string $primaryId,
        public ?string $secondaryId = null,
    ) {
    }

    public static function component(string $id): self
    {
        return new self(SubjectKind::Component, $id);
    }

    public static function flow(string $sourceId, string $targetId): self
    {
        return new self(SubjectKind::Flow, $sourceId, $targetId);
    }

    public static function boundary(string $id): self
    {
        return new self(SubjectKind::Boundary, $id);
    }

    public static function dataAsset(string $id): self
    {
        return new self(SubjectKind::DataAsset, $id);
    }

    public static function model(): self
    {
        return new self(SubjectKind::Model, '');
    }

    public static function parse(string $ref): self
    {
        $parts = explode(':', $ref, 2);
        if (count($parts) !== 2) {
            throw new InvalidArgumentException("Malformed subject ref: {$ref}");
        }

        $kind = SubjectKind::tryFrom($parts[0])
            ?? throw new InvalidArgumentException("Unknown subject kind: {$parts[0]}");

        if ($kind === SubjectKind::Flow) {
            $ends = explode('->', $parts[1], 2);
            if (count($ends) !== 2) {
                throw new InvalidArgumentException("Malformed flow ref: {$ref}");
            }

            return self::flow($ends[0], $ends[1]);
        }

        return new self($kind, $parts[1]);
    }

    public function __toString(): string
    {
        if ($this->kind === SubjectKind::Model) {
            return 'model:';
        }

        if ($this->kind === SubjectKind::Flow) {
            return sprintf('flow:%s->%s', $this->primaryId, (string) $this->secondaryId);
        }

        return sprintf('%s:%s', $this->kind->value, $this->primaryId);
    }

    public function jsonSerialize(): string
    {
        return (string) $this;
    }
}
