<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Confidentiality: string {
    case Public = 'public';
    case Internal = 'internal';
    case Restricted = 'restricted';
    case Confidential = 'confidential';
    case StrictlyConfidential = 'strictly-confidential';

    /**
     * Ordinal rank, 1 (public) .. 5 (strictly confidential).
     *
     * The enum's declaration order already matches this ranking, but rule
     * expressions need a real ordinal to compare against — `>=` on the raw
     * string values would sort alphabetically ("confidential" < "internal"),
     * not by sensitivity.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Public               => 1,
            self::Internal             => 2,
            self::Restricted           => 3,
            self::Confidential         => 4,
            self::StrictlyConfidential => 5,
        };
    }

    public function isAtLeast(self $threshold): bool
    {
        return $this->rank() >= $threshold->rank();
    }
}
