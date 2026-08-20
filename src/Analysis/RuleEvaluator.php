<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Stride;
use HybridTM\Kb\Kind;
use HybridTM\Kb\KnowledgeBaseInterface;

/**
 * Evaluates one declarative KB `Rule` (§4.6, levels 1-2: `when`/`unless`/
 * `then`) against a single subject, producing a `RuleTrace` and any
 * `Finding`s its `then.raise` actions produce.
 *
 * `spec.impl` rules (level 3, PHP `RuleInterface` implementations, T-3.6)
 * are not handled here — `RuleEngine` skips them for now, since loading and
 * instantiating arbitrary KB-referenced classes is a distinct, security-
 * relevant concern deserving its own pass.
 */
final class RuleEvaluator
{
    public function __construct(
        private readonly RuleExpressionProvider $expressions,
        private readonly KnowledgeBaseInterface $kb,
    ) {
    }

    /**
     * @param array<string, mixed> $ruleSpec resolved Rule spec (scope/when/unless/then)
     * @param array<string, mixed> $context single entry, e.g. ['component' => $subject]
     * @return array{trace: RuleTrace, findings: list<Finding>}
     */
    public function evaluate(string $ruleId, array $ruleSpec, SubjectRef $subject, array $context): array
    {
        $conditions = [];

        [$whenMatched, $whenResults] = $this->evaluateGroup($ruleSpec['when'] ?? [], $context, ConditionResult::KIND_WHEN);
        $conditions = [...$conditions, ...$whenResults];

        $unlessMatched = false;
        if (isset($ruleSpec['unless'])) {
            [$unlessMatched, $unlessResults] = $this->evaluateGroup($ruleSpec['unless'], $context, ConditionResult::KIND_UNLESS);
            $conditions = [...$conditions, ...$unlessResults];
        }

        $matched = $whenMatched && !$unlessMatched;
        $trace = new RuleTrace($ruleId, $conditions, $matched);

        $findings = [];
        if ($matched) {
            foreach ($ruleSpec['then'] ?? [] as $action) {
                if (isset($action['raise'])) {
                    $finding = $this->buildFinding($ruleId, $action, $subject, $context, $trace);
                    if ($finding !== null) {
                        $findings[] = $finding;
                    }
                }
                // 'suggest_fix' actions (auto-fix suggestions, T-7.12) are UI
                // affordances, not findings — nothing to do with them here.
            }
        }

        return ['trace' => $trace, 'findings' => $findings];
    }

    /**
     * @param array{all?: list<string>, any?: list<string>} $group
     * @param array<string, mixed> $context
     * @return array{0: bool, 1: list<ConditionResult>}
     */
    private function evaluateGroup(array $group, array $context, string $kind): array
    {
        $results = [];

        $allPassed = true;
        foreach ($group['all'] ?? [] as $expression) {
            $passed = $this->safeEvaluate($expression, $context, $results, $kind);
            $allPassed = $allPassed && $passed;
        }

        $anyPassed = ($group['any'] ?? []) === [];
        foreach ($group['any'] ?? [] as $expression) {
            $passed = $this->safeEvaluate($expression, $context, $results, $kind);
            $anyPassed = $anyPassed || $passed;
        }

        return [$allPassed && $anyPassed, $results];
    }

    /**
     * @param array<string, mixed> $context
     * @param list<ConditionResult> $results appended to by reference
     */
    private function safeEvaluate(string $expression, array $context, array &$results, string $kind): bool
    {
        try {
            $passed = (bool) $this->expressions->evaluate($expression, $context);
            $results[] = new ConditionResult($expression, $passed, $kind);
            return $passed;
        } catch (RuleExpressionException $e) {
            // Fail closed: a broken expression never fires a rule and never
            // suppresses one either — it just shows up in the trace for
            // whoever authored the rule to fix.
            $results[] = new ConditionResult($expression, false, $kind, $e->getMessage());
            return false;
        }
    }

    /**
     * @param array<string, mixed> $action one `then[]` entry with a 'raise' key
     * @param array<string, mixed> $context
     */
    private function buildFinding(string $ruleId, array $action, SubjectRef $subject, array $context, RuleTrace $trace): ?Finding
    {
        $threatId = (string) $action['raise'];
        $threat = $this->kb->get(Kind::Threat, $threatId);
        if ($threat === null) {
            return null;
        }

        $likelihood = Likelihood::tryFrom($this->safeRender((string) ($action['likelihood'] ?? ''), $context))
            ?? Likelihood::tryFrom((string) ($threat['base']['likelihood'] ?? ''))
            ?? Likelihood::Likely;
        $impact = Impact::tryFrom($this->safeRender((string) ($action['impact'] ?? ''), $context))
            ?? Impact::tryFrom((string) ($threat['base']['impact'] ?? ''))
            ?? Impact::Medium;

        $evidenceText = isset($action['evidence']) ? $this->safeRender((string) $action['evidence'], $context) : '';

        return Finding::create(
            threatId: $threatId,
            ruleId: $ruleId,
            subject: $subject,
            title: (string) ($threat['title'] ?? $threatId),
            likelihood: $likelihood,
            impact: $impact,
            source: FindingSource::HybridTM,
            description: (string) ($threat['summary'] ?? ''),
            stride: array_values(array_filter(array_map(
                static fn ($s): ?Stride => Stride::tryFrom((string) $s),
                $threat['stride'] ?? [],
            ))),
            evidence: $evidenceText !== '' ? [$evidenceText] : [],
            countermeasureIds: array_values(array_unique([
                ...($threat['countermeasures'] ?? []),
                ...($action['require'] ?? []),
            ])),
            standards: $this->buildStandardsMapping($threat['standards'] ?? []),
            trace: $trace,
        );
    }

    /**
     * @param array<string, mixed> $context
     *                                      Renders a `then[]` action string, falling back to the raw text on any
     *                                      evaluation error (e.g. an expression referencing a method the current
     *                                      Subject wrappers don't implement) — a bad `impact`/`evidence` template
     *                                      must never abort the whole analysis run.
     */
    private function safeRender(string $template, array $context): string
    {
        try {
            return $this->expressions->render($template, $context);
        } catch (RuleExpressionException) {
            return '';
        }
    }

    /** @param array<string, mixed> $standards */
    private function buildStandardsMapping(array $standards): StandardsMapping
    {
        return new StandardsMapping(
            cwe: array_values(array_map(static fn ($v): int => (int) $v, $standards['cwe'] ?? [])),
            capec: array_values(array_map(static fn ($v): int => (int) $v, $standards['capec'] ?? [])),
            owaspTop10: $standards['owasp_top10_2021'] ?? [],
            owaspAsvs: $standards['owasp_asvs'] ?? [],
            mitreAttack: $standards['mitre_attack'] ?? [],
            pciDss: $standards['pci_dss_4'] ?? [],
            iso27001: $standards['iso_27001_2022'] ?? [],
            nist80053: $standards['nist_800_53'] ?? [],
        );
    }
}
