<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

use HybridTM\Analysis\Rules\PhpRuleLoader;
use HybridTM\Analysis\Rules\RuleContext;
use HybridTM\Analysis\Rules\RuleContextGraph;
use HybridTM\Analysis\Rules\RuleContextModel;
use HybridTM\Analysis\Subjects\BoundarySubject;
use HybridTM\Analysis\Subjects\ComponentSubject;
use HybridTM\Analysis\Subjects\FlowSubject;
use HybridTM\Analysis\Subjects\ModelSubject;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\Kind;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Kb\RuleScope;
use HybridTM\Validation\ModelValidator;
use HybridTM\Validation\ModelValidatorInterface;

/**
 * Reference `AnalyzerInterface` implementation: the 11-phase pipeline from
 * §5.2, minus the phases that depend on work landing in later tasks —
 * each gap is called out below rather than silently skipped.
 *
 *  0. Expand      — no-op. ComponentExpander (T-2.10) doesn't exist yet;
 *                   there is nothing to expand a KB component into.
 *  1. Normalize   — folded into building the ModelIndex, which is itself
 *                   already a normalized read-only view (sorted lookups,
 *                   deduplicated by construction). No separate mutation
 *                   pass over the caller's ThreatModel.
 *  2. Validate    — ModelValidator; an Error-level issue stops the
 *                   pipeline here, matching §5.2 ("Error -> стоп").
 *  3. Derive      — DeriveEngine.
 *  4-7. *rules    — declarative (when/unless/then) rules run per subject;
 *                   `spec.impl` PHP rules (T-3.6) run once each, given the
 *                   whole model, and decide their own subjects.
 *  8. Suppress    — `unless` is handled inline per rule (§ RuleEvaluator).
 *                   Resolved `riskTracking` entries additionally drop a
 *                   matching finding unless `includeSuppressed` is set.
 *                   #[Mitigation]-from-code suppression is NOT implemented:
 *                   AnalyzerInterface::analyze() has no parameter carrying
 *                   AstScanner output, so there is nothing to suppress with
 *                   yet — a signature change, not something to fake here.
 *  9. Score       — Finding::create() computes the base severity from
 *                   likelihood x impact via Severity::calculate();
 *                   SeverityModifierEngine then applies 5 of the 8 §5.3
 *                   contextual modifiers (exposure x2, sensitivity x2,
 *                   volume) — the other 3 need data this engine version
 *                   doesn't have (see that class's docblock for why).
 * 10. Dedup&merge — findings this engine itself produced for the same
 *                   (rule, threat, subject) are merged via Finding::mergeWith().
 *                   Merging against a separate Threagile run is T-5.4 and
 *                   needs a Threagile bridge that doesn't exist yet.
 */
final class RuleEngine implements AnalyzerInterface
{
    private const ENGINE_VERSION = '0.1.0';

    private RuleExpressionProvider $expressions;
    private ModelValidatorInterface $validator;
    private PhpRuleLoader $phpRules;

    public function __construct(
        ?RuleExpressionProvider $expressions = null,
        ?ModelValidatorInterface $validator = null,
        ?PhpRuleLoader $phpRules = null,
    ) {
        // Reuse across analyze() calls to benefit from the expression
        // language's internal parse cache (T-3.3) — construct one
        // RuleEngine and call analyze() on it repeatedly, rather than a
        // fresh RuleEngine per run.
        $this->expressions = $expressions ?? new RuleExpressionProvider();
        $this->validator = $validator ?? new ModelValidator();
        $this->phpRules = $phpRules ?? new PhpRuleLoader();
    }

    public function analyze(
        ThreatModel $model,
        KnowledgeBaseInterface $kb,
        AnalysisOptions $options = new AnalysisOptions(),
    ): AnalysisResult {
        $start = hrtime(true);
        $phaseDurations = [];
        $inputHash = $this->inputHash($model, $kb);

        $validationStart = hrtime(true);
        $validation = $this->validator->validate($model);
        $phaseDurations['validate'] = $this->elapsedMs($validationStart);

        if ($validation->hasErrors()) {
            return new AnalysisResult(
                findings: [],
                validation: $validation,
                stats: new AnalysisStats(
                    durationMs: $this->elapsedMs($start),
                    phaseDurationsMs: $phaseDurations,
                    engineVersion: self::ENGINE_VERSION,
                    kbVersion: $kb->version(),
                ),
                inputHash: $inputHash,
            );
        }

        $indexStart = hrtime(true);
        $index = ModelIndex::build($model);
        $phaseDurations['index'] = $this->elapsedMs($indexStart);

        $deriveStart = hrtime(true);
        $derived = (new DeriveEngine())->derive($model, $index);
        $phaseDurations['derive'] = $this->elapsedMs($deriveStart);

        $evaluator = new RuleEvaluator($this->expressions, $kb);
        $findings = [];
        $rulesEvaluated = 0;

        $rulesStart = hrtime(true);

        [$componentFindings, $evaluatedComponent] = $this->evaluateComponentRules($model, $kb, $evaluator, $derived, $options);
        $findings = [...$findings, ...$componentFindings];
        $rulesEvaluated += $evaluatedComponent;

        [$flowFindings, $evaluatedFlow] = $this->evaluateFlowRules($model, $kb, $evaluator, $index, $derived, $options);
        $findings = [...$findings, ...$flowFindings];
        $rulesEvaluated += $evaluatedFlow;

        [$boundaryFindings, $evaluatedBoundary] = $this->evaluateBoundaryRules($model, $kb, $evaluator, $derived, $options);
        $findings = [...$findings, ...$boundaryFindings];
        $rulesEvaluated += $evaluatedBoundary;

        [$modelFindings, $evaluatedModel] = $this->evaluateModelRules($model, $kb, $evaluator, $options);
        $findings = [...$findings, ...$modelFindings];
        $rulesEvaluated += $evaluatedModel;

        [$phpFindings, $evaluatedPhp] = $this->evaluatePhpRules($model, $kb, $index, $derived, $options);
        $findings = [...$findings, ...$phpFindings];
        $rulesEvaluated += $evaluatedPhp;

        $phaseDurations['rules'] = $this->elapsedMs($rulesStart);

        $scoreStart = hrtime(true);
        $modifiers = new SeverityModifierEngine();
        $findings = array_map(
            static fn (Finding $f): Finding => $modifiers->apply($f, $model, $index, $derived),
            $findings,
        );
        $phaseDurations['score'] = $this->elapsedMs($scoreStart);

        $findings = $this->suppressResolvedRisks($model, $findings, $options);
        $findings = $this->dedupAndMerge($findings);
        $findings = array_values(array_filter(
            $findings,
            static fn (Finding $f): bool => $f->severity->isAtLeast($options->minSeverity),
        ));

        return new AnalysisResult(
            findings: $findings,
            validation: $validation,
            stats: new AnalysisStats(
                rulesEvaluated: $rulesEvaluated,
                rulesMatched: count($findings),
                durationMs: $this->elapsedMs($start),
                phaseDurationsMs: $phaseDurations,
                engineVersion: self::ENGINE_VERSION,
                kbVersion: $kb->version(),
            ),
            inputHash: $inputHash,
        );
    }

    /** @return array{0: list<Finding>, 1: int} */
    private function evaluateComponentRules(ThreatModel $model, KnowledgeBaseInterface $kb, RuleEvaluator $evaluator, DerivedTraits $derived, AnalysisOptions $options): array
    {
        $ruleIds = $this->selectRuleIds($kb, RuleScope::Component, $options);
        $findings = [];
        $evaluated = 0;

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            $subject = new ComponentSubject($asset, $model, $derived);
            $context = ['component' => $subject];

            foreach ($ruleIds as $ruleId) {
                $spec = $kb->get(Kind::Rule, $ruleId);
                if ($spec === null || isset($spec['impl'])) {
                    continue;
                }
                ++$evaluated;
                $result = $evaluator->evaluate($ruleId, $spec, SubjectRef::component($assetId), $context);
                $findings = [...$findings, ...$result['findings']];
            }
        }

        return [$findings, $evaluated];
    }

    /** @return array{0: list<Finding>, 1: int} */
    private function evaluateFlowRules(ThreatModel $model, KnowledgeBaseInterface $kb, RuleEvaluator $evaluator, ModelIndex $index, DerivedTraits $derived, AnalysisOptions $options): array
    {
        $ruleIds = $this->selectRuleIds($kb, RuleScope::Flow, $options);
        $findings = [];
        $evaluated = 0;

        foreach ($model->getTechnicalAssets() as $sourceId => $asset) {
            foreach ($asset->communicationLinks as $link) {
                if ($model->getTechnicalAsset($link->targetAssetId) === null) {
                    continue; // dangling link — Validate should already have stopped the pipeline
                }

                $subject = new FlowSubject($link, $sourceId, $model, $index, $derived);
                $context = ['flow' => $subject];

                foreach ($ruleIds as $ruleId) {
                    $spec = $kb->get(Kind::Rule, $ruleId);
                    if ($spec === null || isset($spec['impl'])) {
                        continue;
                    }
                    ++$evaluated;
                    $result = $evaluator->evaluate($ruleId, $spec, SubjectRef::flow($sourceId, $link->targetAssetId), $context);
                    $findings = [...$findings, ...$result['findings']];
                }
            }
        }

        return [$findings, $evaluated];
    }

    /** @return array{0: list<Finding>, 1: int} */
    private function evaluateBoundaryRules(ThreatModel $model, KnowledgeBaseInterface $kb, RuleEvaluator $evaluator, DerivedTraits $derived, AnalysisOptions $options): array
    {
        $ruleIds = $this->selectRuleIds($kb, RuleScope::Boundary, $options);
        $findings = [];
        $evaluated = 0;

        foreach ($model->getTrustBoundaries() as $boundaryId => $boundary) {
            $subject = new BoundarySubject($boundary, $model, $derived);
            $context = ['boundary' => $subject];

            foreach ($ruleIds as $ruleId) {
                $spec = $kb->get(Kind::Rule, $ruleId);
                if ($spec === null || isset($spec['impl'])) {
                    continue;
                }
                ++$evaluated;
                $result = $evaluator->evaluate($ruleId, $spec, SubjectRef::boundary($boundaryId), $context);
                $findings = [...$findings, ...$result['findings']];
            }
        }

        return [$findings, $evaluated];
    }

    /** @return array{0: list<Finding>, 1: int} */
    private function evaluateModelRules(ThreatModel $model, KnowledgeBaseInterface $kb, RuleEvaluator $evaluator, AnalysisOptions $options): array
    {
        $ruleIds = $this->selectRuleIds($kb, RuleScope::Model, $options);
        $subject = new ModelSubject($model);
        $context = ['model' => $subject];
        $findings = [];
        $evaluated = 0;

        foreach ($ruleIds as $ruleId) {
            $spec = $kb->get(Kind::Rule, $ruleId);
            if ($spec === null || isset($spec['impl'])) {
                continue;
            }
            ++$evaluated;
            $result = $evaluator->evaluate($ruleId, $spec, SubjectRef::model(), $context);
            $findings = [...$findings, ...$result['findings']];
        }

        return [$findings, $evaluated];
    }

    /**
     * Runs every `spec.impl` rule exactly once, across all scopes — unlike
     * declarative rules, a PHP rule decides its own subjects (§4.6 level 3),
     * so there is no per-asset/per-flow loop to run it inside.
     *
     * @return array{0: list<Finding>, 1: int}
     */
    private function evaluatePhpRules(ThreatModel $model, KnowledgeBaseInterface $kb, ModelIndex $index, DerivedTraits $derived, AnalysisOptions $options): array
    {
        $ruleIds = array_unique([
            ...$this->selectRuleIds($kb, RuleScope::Component, $options),
            ...$this->selectRuleIds($kb, RuleScope::Flow, $options),
            ...$this->selectRuleIds($kb, RuleScope::Boundary, $options),
            ...$this->selectRuleIds($kb, RuleScope::Model, $options),
        ]);

        $contextModel = new RuleContextModel($model, $derived);
        $contextGraph = new RuleContextGraph($model, $index, $derived);
        $findings = [];
        $evaluated = 0;

        foreach ($ruleIds as $ruleId) {
            $spec = $kb->get(Kind::Rule, $ruleId);
            if ($spec === null || !isset($spec['impl'])) {
                continue;
            }

            ++$evaluated;
            $rule = $this->phpRules->load((string) $spec['impl']);
            $ctx = new RuleContext($ruleId, $contextModel, $contextGraph, $kb, (array) ($spec['config'] ?? []));

            foreach ($rule->evaluate($ctx) as $finding) {
                if ($finding !== null) {
                    $findings[] = $finding;
                }
            }
        }

        return [$findings, $evaluated];
    }

    /** @return list<string> */
    private function selectRuleIds(KnowledgeBaseInterface $kb, RuleScope $scope, AnalysisOptions $options): array
    {
        $ruleIds = $kb->rulesFor($scope);

        if ($options->onlyRules !== []) {
            $ruleIds = array_values(array_intersect($ruleIds, $options->onlyRules));
        }
        if ($options->skipRules !== []) {
            $ruleIds = array_values(array_diff($ruleIds, $options->skipRules));
        }

        return $ruleIds;
    }

    /**
     * @param list<Finding> $findings
     * @return list<Finding>
     */
    private function suppressResolvedRisks(ThreatModel $model, array $findings, AnalysisOptions $options): array
    {
        if ($options->includeSuppressed) {
            return $findings;
        }

        // Convention: a RiskTracking entry's syntheticRiskId is the stableId
        // of the Finding it decides — how a UI wires "accept this risk" to
        // the model (ADR-12). Threagile's own synthetic risk ids are a
        // different format entirely; reconciling the two belongs to the
        // Threagile bridge (T-5.6), not here.
        $tracking = $model->getRiskTracking();

        return array_values(array_filter(
            $findings,
            static function (Finding $f) use ($tracking): bool {
                $decision = $tracking[$f->stableId] ?? null;
                return $decision === null || !$decision->status->isResolved();
            },
        ));
    }

    /**
     * @param list<Finding> $findings
     * @return list<Finding>
     */
    private function dedupAndMerge(array $findings): array
    {
        /** @var array<string, Finding> $byStableId */
        $byStableId = [];
        foreach ($findings as $finding) {
            $byStableId[$finding->stableId] = isset($byStableId[$finding->stableId])
                ? $byStableId[$finding->stableId]->mergeWith($finding)
                : $finding;
        }

        return array_values($byStableId);
    }

    private function inputHash(ThreatModel $model, KnowledgeBaseInterface $kb): string
    {
        $modelFingerprint = [];
        foreach ($model->getTechnicalAssets() as $id => $asset) {
            $modelFingerprint[] = $id . ':' . $asset->technology->value . ':' . implode(',', $asset->traits);
        }
        foreach ($model->getTechnicalAssets() as $id => $asset) {
            foreach ($asset->communicationLinks as $link) {
                $modelFingerprint[] = $link->id . '->' . $link->targetAssetId;
            }
        }
        sort($modelFingerprint);

        return hash('sha256', $model->title . '|' . implode(';', $modelFingerprint) . '|' . $kb->version());
    }

    private function elapsedMs(int $startNanos): float
    {
        return (hrtime(true) - $startNanos) / 1_000_000;
    }
}
