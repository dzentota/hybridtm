<?php
declare(strict_types=1);
namespace HybridTM\Analysis\Rules;

use HybridTM\Analysis\Finding;
use HybridTM\Analysis\StandardsMapping;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Stride;
use HybridTM\Kb\Kind;
use HybridTM\Kb\KnowledgeBaseInterface;

/** Everything a level-3 PHP `RuleInterface::evaluate()` needs (§4.6). */
final readonly class RuleContext
{
    /** @param array<string, mixed> $config this rule's own `spec.config` block */
    public function __construct(
        public string $ruleId,
        public RuleContextModel $model,
        public RuleContextGraph $graph,
        private KnowledgeBaseInterface $kb,
        private array $config = [],
    ) {
    }

    public function config(string $key, mixed $default = null): mixed
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Builds a `Finding` for the given threat, looking title/description/
     * stride/standards/base-severity up from the KB — the same shape a
     * declarative rule's `then.raise` produces, so both kinds of rule feed
     * the same downstream pipeline (Suppress, Score, Dedup&merge).
     *
     * @param list<string> $require additional countermeasure ids beyond the threat's own
     */
    public function raise(
        string $threat,
        SubjectRef $subject,
        Likelihood $likelihood,
        Impact $impact,
        string $evidence = '',
        array $require = [],
    ): ?Finding {
        $spec = $this->kb->get(Kind::Threat, $threat);
        if ($spec === null) {
            return null;
        }

        return Finding::create(
            threatId: $threat,
            ruleId: $this->ruleId,
            subject: $subject,
            title: (string) ($spec['title'] ?? $threat),
            likelihood: $likelihood,
            impact: $impact,
            source: FindingSource::HybridTM,
            description: (string) ($spec['summary'] ?? ''),
            stride: array_values(array_filter(array_map(
                static fn ($s): ?Stride => Stride::tryFrom((string) $s),
                $spec['stride'] ?? [],
            ))),
            evidence: $evidence !== '' ? [$evidence] : [],
            countermeasureIds: array_values(array_unique([...($spec['countermeasures'] ?? []), ...$require])),
            standards: new StandardsMapping(
                cwe: array_map(static fn ($v): int => (int) $v, $spec['standards']['cwe'] ?? []),
                capec: array_map(static fn ($v): int => (int) $v, $spec['standards']['capec'] ?? []),
                owaspTop10: $spec['standards']['owasp_top10_2021'] ?? [],
                owaspAsvs: $spec['standards']['owasp_asvs'] ?? [],
                mitreAttack: $spec['standards']['mitre_attack'] ?? [],
                pciDss: $spec['standards']['pci_dss_4'] ?? [],
                iso27001: $spec['standards']['iso_27001_2022'] ?? [],
                nist80053: $spec['standards']['nist_800_53'] ?? [],
            ),
        );
    }
}
