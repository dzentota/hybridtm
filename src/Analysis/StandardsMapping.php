<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

/**
 * Cross-references to external catalogues. Every field is optional —
 * a threat maps to whatever standards actually apply to it.
 */
final readonly class StandardsMapping implements \JsonSerializable
{
    /**
     * @param list<int>    $cwe            e.g. [311, 312]
     * @param list<int>    $capec          e.g. [37]
     * @param list<string> $owaspTop10     e.g. ['A02:2021']
     * @param list<string> $owaspAsvs      e.g. ['V6.2.1']
     * @param list<string> $mitreAttack    e.g. ['T1005']
     * @param list<string> $pciDss         e.g. ['3.5.1']
     * @param list<string> $iso27001       e.g. ['A.8.24']
     * @param list<string> $nist80053      e.g. ['SC-28']
     */
    public function __construct(
        public array $cwe = [],
        public array $capec = [],
        public array $owaspTop10 = [],
        public array $owaspAsvs = [],
        public array $mitreAttack = [],
        public array $pciDss = [],
        public array $iso27001 = [],
        public array $nist80053 = [],
    ) {
    }

    public function hasCwe(int $cwe): bool
    {
        return in_array($cwe, $this->cwe, true);
    }

    /** @return array<string, list<int>|list<string>> */
    public function jsonSerialize(): array
    {
        return array_filter([
            'cwe'         => $this->cwe,
            'capec'       => $this->capec,
            'owaspTop10'  => $this->owaspTop10,
            'owaspAsvs'   => $this->owaspAsvs,
            'mitreAttack' => $this->mitreAttack,
            'pciDss'      => $this->pciDss,
            'iso27001'    => $this->iso27001,
            'nist80053'   => $this->nist80053,
        ], static fn (array $v): bool => $v !== []);
    }
}
