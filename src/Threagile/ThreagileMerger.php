<?php
declare(strict_types=1);
namespace HybridTM\Threagile;

use HybridTM\Analysis\Finding;
use HybridTM\Enums\FindingSource;

/**
 * Merges HybridTM's own findings with Threagile's, deduplicated via
 * `ThreagileCategoryMap` (§5.4, T-5.4): agreement between two independent
 * engines on the same (threat, subject) is a strong signal, not noise to
 * show twice.
 *
 * `Finding::mergeWith()` requires both sides to already share a
 * `stableId` — but a Threagile-sourced Finding's `ruleId` is its Threagile
 * *category*, which is never going to match one of our own rule ids. This
 * class bridges that: for a `merge`-strategy category, it looks up
 * whichever HybridTM finding already exists for the mapped threat id and
 * the same subject, rebuilds the Threagile side under *that* finding's own
 * `(ruleId, threatId)` so the stable ids align, and only then merges them
 * — the merged finding keeps HybridTM's ruleId/stableId (what
 * `RiskTracking` decisions are keyed against, ADR-12), with Threagile
 * recorded in `corroboratedBy`.
 */
final class ThreagileMerger
{
    public function __construct(private readonly ThreagileCategoryMap $categoryMap = new ThreagileCategoryMap())
    {
    }

    /**
     * @param list<Finding> $hybridTmFindings
     * @param list<Finding> $threagileFindings raw output of `ThreagileRiskParser`
     *        (`ruleId` = Threagile category, `threatId` = "THREAGILE-{category}")
     * @return list<Finding>
     */
    public function merge(array $hybridTmFindings, array $threagileFindings): array
    {
        $result = array_values($hybridTmFindings);

        $indexByKey = [];
        foreach ($result as $i => $finding) {
            $indexByKey[$this->key($finding->threatId, (string) $finding->subject)] = $i;
        }

        foreach ($threagileFindings as $threagileFinding) {
            $category = $threagileFinding->ruleId;
            $strategy = $this->categoryMap->strategyFor($category);

            if ($strategy === MergeStrategy::ValidationOnly) {
                // A model-quality problem, not a risk — ModelValidator's job
                // (§3.6), not this register's.
                continue;
            }

            if ($strategy === MergeStrategy::ThreagileOnly) {
                $result[] = $threagileFinding;
                continue;
            }

            $mappedThreatId = $this->categoryMap->threatIdFor($category) ?? $threagileFinding->threatId;
            $key = $this->key($mappedThreatId, (string) $threagileFinding->subject);

            if (isset($indexByKey[$key])) {
                $ours = $result[$indexByKey[$key]];
                $theirs = $this->rebuildUnder($threagileFinding, $ours->ruleId, $mappedThreatId);
                $result[$indexByKey[$key]] = $ours->mergeWith($theirs);
                continue;
            }

            // Threagile found something of ours mapped nothing matches yet —
            // still a real risk, just not corroborated by our own rules.
            $result[] = $this->rebuildUnder($threagileFinding, "threagile/{$category}", $mappedThreatId);
        }

        return array_values($result);
    }

    private function rebuildUnder(Finding $finding, string $ruleId, string $threatId): Finding
    {
        return Finding::create(
            threatId: $threatId,
            ruleId: $ruleId,
            subject: $finding->subject,
            title: $finding->title,
            likelihood: $finding->likelihood,
            impact: $finding->impact,
            source: FindingSource::Threagile,
            description: $finding->description,
            stride: $finding->stride,
            evidence: $finding->evidence,
            countermeasureIds: $finding->countermeasureIds,
            standards: $finding->standards,
        );
    }

    private function key(string $threatId, string $subject): string
    {
        return $threatId . "\0" . $subject;
    }
}
