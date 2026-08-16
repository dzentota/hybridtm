<?php
declare(strict_types=1);
namespace HybridTM\Risk;

use HybridTM\Analysis\Finding;
use HybridTM\DSL\ThreatModel;

/**
 * The Unified Risk Register (§5.6): every finding (from either engine,
 * already merged via `ThreagileMerger` upstream), the decisions taken on
 * them, a severity summary, and coverage.
 *
 * `coverage` is a simplification worth being explicit about: it reports
 * the share of technical assets that have *at least one finding
 * attached*, as a proxy for "at least one rule engaged with this asset".
 * The plan's own wording ("% of components with at least one *evaluated*
 * rule") would need `AnalysisStats` to track which rules ran against
 * which specific asset, not just a total rules-evaluated count — that
 * level of detail isn't exposed yet, so this reports the nearest thing
 * that is: assets that produced a result, not assets that were merely
 * checked and came back clean.
 */
final readonly class RiskRegister
{
    /**
     * @param list<Finding> $findings
     * @param list<RiskDecision> $decisions
     * @param array{coveredAssets: int, totalAssets: int, percentage: float} $coverage
     */
    public function __construct(
        public array $findings,
        public array $decisions,
        public RiskSummary $summary,
        public array $coverage,
    ) {
    }

    /**
     * @param list<Finding> $findings
     * @param list<RiskDecision> $decisions
     */
    public static function build(array $findings, array $decisions, ThreatModel $model): self
    {
        return new self(
            findings: $findings,
            decisions: $decisions,
            summary: RiskSummary::from($findings),
            coverage: self::computeCoverage($findings, $model),
        );
    }

    public function decisionFor(string $findingStableId): ?RiskDecision
    {
        foreach ($this->decisions as $decision) {
            if ($decision->findingStableId === $findingStableId) {
                return $decision;
            }
        }
        return null;
    }

    /**
     * @param list<Finding> $findings
     * @return array{coveredAssets: int, totalAssets: int, percentage: float}
     */
    private static function computeCoverage(array $findings, ThreatModel $model): array
    {
        $totalAssets = count($model->getTechnicalAssets());
        if ($totalAssets === 0) {
            return ['coveredAssets' => 0, 'totalAssets' => 0, 'percentage' => 0.0];
        }

        $coveredIds = [];
        foreach ($findings as $finding) {
            $assetId = $finding->subject->primaryId;
            if ($model->getTechnicalAsset($assetId) !== null) {
                $coveredIds[$assetId] = true;
            }
        }

        $covered = count($coveredIds);
        return [
            'coveredAssets' => $covered,
            'totalAssets' => $totalAssets,
            'percentage' => round(($covered / $totalAssets) * 100, 1),
        ];
    }
}
