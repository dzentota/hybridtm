<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Severity;
use HybridTM\Enums\Stride;

/**
 * A single risk finding.
 *
 * `stableId` is deterministic across runs (ADR-12): it depends only on the
 * rule, the threat and the subject — never on names, ordering or timestamps.
 * That is what lets a risk decision taken three sprints ago still apply.
 */
final readonly class Finding implements \JsonSerializable
{
    /**
     * @param list<string>      $evidence           human-readable reasons, rendered in the UI
     * @param list<Stride>      $stride
     * @param list<string>      $countermeasureIds
     * @param list<FindingSource> $corroboratedBy   other engines that reported the same thing
     */
    public function __construct(
        public string $stableId,
        public string $threatId,
        public string $ruleId,
        public FindingSource $source,
        public SubjectRef $subject,
        public string $title,
        public string $description,
        public Likelihood $likelihood,
        public Impact $impact,
        public Severity $severity,
        public array $stride = [],
        public array $evidence = [],
        public array $countermeasureIds = [],
        public StandardsMapping $standards = new StandardsMapping(),
        public ?RuleTrace $trace = null,
        public ?MitigationEvidence $mitigation = null,
        public ?CodeLocation $codeLocation = null,
        public array $corroboratedBy = [],
    ) {
    }

    /**
     * Preferred constructor: derives severity from the scale and the stable id
     * from (rule, threat, subject) so callers cannot get either wrong.
     *
     * @param list<string> $evidence
     * @param list<Stride> $stride
     * @param list<string> $countermeasureIds
     */
    public static function create(
        string $threatId,
        string $ruleId,
        SubjectRef $subject,
        string $title,
        Likelihood $likelihood,
        Impact $impact,
        FindingSource $source = FindingSource::HybridTM,
        string $description = '',
        array $stride = [],
        array $evidence = [],
        array $countermeasureIds = [],
        StandardsMapping $standards = new StandardsMapping(),
        ?RuleTrace $trace = null,
        ?MitigationEvidence $mitigation = null,
        ?CodeLocation $codeLocation = null,
    ): self {
        return new self(
            stableId: self::stableId($ruleId, $threatId, $subject),
            threatId: $threatId,
            ruleId: $ruleId,
            source: $source,
            subject: $subject,
            title: $title,
            description: $description,
            likelihood: $likelihood,
            impact: $impact,
            severity: Severity::calculate($likelihood, $impact),
            stride: $stride,
            evidence: $evidence,
            countermeasureIds: $countermeasureIds,
            standards: $standards,
            trace: $trace,
            mitigation: $mitigation,
            codeLocation: $codeLocation,
        );
    }

    public static function stableId(string $ruleId, string $threatId, SubjectRef $subject): string
    {
        return substr(hash('sha256', $ruleId . "\0" . $threatId . "\0" . (string) $subject), 0, 32);
    }

    /**
     * Merge a finding reported by another engine for the same threat and
     * subject: keep the higher severity, union the evidence, record the
     * corroborating source. Agreement between engines is a strong signal.
     */
    public function mergeWith(self $other): self
    {
        if ($other->stableId !== $this->stableId) {
            throw new \InvalidArgumentException(
                "Refusing to merge findings with different stable ids: {$this->stableId} vs {$other->stableId}",
            );
        }

        $winner = $other->severity->rank() > $this->severity->rank() ? $other : $this;
        $sources = $this->corroboratedBy;
        if (!in_array($other->source, $sources, true) && $other->source !== $this->source) {
            $sources[] = $other->source;
        }

        return new self(
            stableId: $this->stableId,
            threatId: $this->threatId,
            ruleId: $this->ruleId,
            source: $this->source,
            subject: $this->subject,
            title: $this->title,
            description: $this->description !== '' ? $this->description : $other->description,
            likelihood: $winner->likelihood,
            impact: $winner->impact,
            severity: $winner->severity,
            stride: $this->stride !== [] ? $this->stride : $other->stride,
            evidence: array_values(array_unique([...$this->evidence, ...$other->evidence])),
            countermeasureIds: array_values(array_unique([...$this->countermeasureIds, ...$other->countermeasureIds])),
            standards: $this->standards,
            trace: $this->trace ?? $other->trace,
            mitigation: $this->mitigation ?? $other->mitigation,
            codeLocation: $this->codeLocation ?? $other->codeLocation,
            corroboratedBy: $sources,
        );
    }

    public function withSeverity(Likelihood $likelihood, Impact $impact): self
    {
        return new self(
            stableId: $this->stableId,
            threatId: $this->threatId,
            ruleId: $this->ruleId,
            source: $this->source,
            subject: $this->subject,
            title: $this->title,
            description: $this->description,
            likelihood: $likelihood,
            impact: $impact,
            severity: Severity::calculate($likelihood, $impact),
            stride: $this->stride,
            evidence: $this->evidence,
            countermeasureIds: $this->countermeasureIds,
            standards: $this->standards,
            trace: $this->trace,
            mitigation: $this->mitigation,
            codeLocation: $this->codeLocation,
            corroboratedBy: $this->corroboratedBy,
        );
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'stableId'          => $this->stableId,
            'threatId'          => $this->threatId,
            'ruleId'            => $this->ruleId,
            'source'            => $this->source->value,
            'subject'           => (string) $this->subject,
            'title'             => $this->title,
            'description'       => $this->description,
            'likelihood'        => $this->likelihood->value,
            'impact'            => $this->impact->value,
            'severity'          => $this->severity->value,
            'stride'            => array_map(static fn (Stride $s): string => $s->value, $this->stride),
            'evidence'          => $this->evidence,
            'countermeasureIds' => $this->countermeasureIds,
            'standards'         => $this->standards,
            'trace'             => $this->trace,
            'mitigation'        => $this->mitigation,
            'codeLocation'      => $this->codeLocation,
            'corroboratedBy'    => array_map(static fn (FindingSource $s): string => $s->value, $this->corroboratedBy),
        ];
    }
}
