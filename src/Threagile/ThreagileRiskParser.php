<?php

declare(strict_types=1);

namespace HybridTM\Threagile;

use HybridTM\Analysis\Finding;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;

/**
 * Parses Threagile's `risks.json` into `Finding[]` with `source:
 * FindingSource::Threagile` (T-5.2). Field names and shape confirmed
 * against DefectDojo's Threagile parser documentation and a real example
 * (a flat array of risk objects, not grouped by category) rather than
 * guessed from memory — `category`/`title`/`severity`/`synthetic_id`/
 * `exploitation_likelihood`/`exploitation_impact`/`most_relevant_*` are
 * all real field names, not invented ones.
 *
 * `most_relevant_communication_link`'s exact string encoding (how it packs
 * source and target into one field) isn't confirmed anywhere this parser
 * was built against, so it is deliberately not parsed into a flow
 * `SubjectRef` — guessing a delimiter wrong would silently produce bad
 * subject refs. A risk whose only locator is that field falls back to
 * `SubjectRef::model()`; `most_relevant_technical_asset`,
 * `most_relevant_trust_boundary` and `most_relevant_data_asset` are all
 * single ids and are mapped directly, checked in that priority order.
 */
final class ThreagileRiskParser
{
    /** @return list<Finding> */
    public function parseFile(string $risksJsonPath): array
    {
        $contents = file_get_contents($risksJsonPath);
        if ($contents === false) {
            throw new ThreagileRunException("Could not read risks.json: {$risksJsonPath}");
        }
        return $this->parse($contents);
    }

    /** @return list<Finding> */
    public function parse(string $risksJson): array
    {
        $data = json_decode($risksJson, true);
        if (!is_array($data)) {
            return [];
        }

        return array_values(array_map(
            fn ($risk): Finding => $this->parseRisk((array) $risk),
            $data,
        ));
    }

    /** @param array<string, mixed> $risk */
    private function parseRisk(array $risk): Finding
    {
        $category = (string) ($risk['category'] ?? 'unknown-category');
        $syntheticId = (string) ($risk['synthetic_id'] ?? '');
        $title = (string) ($risk['title'] ?? $category);

        $likelihood = Likelihood::tryFrom((string) ($risk['exploitation_likelihood'] ?? '')) ?? Likelihood::Likely;
        $impact = Impact::tryFrom((string) ($risk['exploitation_impact'] ?? '')) ?? Impact::Medium;

        return Finding::create(
            threatId: 'THREAGILE-' . $category,
            ruleId: $category,
            subject: $this->buildSubjectRef($risk),
            title: $title,
            likelihood: $likelihood,
            impact: $impact,
            source: FindingSource::Threagile,
            description: $title,
            evidence: $syntheticId !== '' ? [$syntheticId] : [],
        );
    }

    /** @param array<string, mixed> $risk */
    private function buildSubjectRef(array $risk): SubjectRef
    {
        if (!empty($risk['most_relevant_technical_asset'])) {
            return SubjectRef::component((string) $risk['most_relevant_technical_asset']);
        }
        if (!empty($risk['most_relevant_trust_boundary'])) {
            return SubjectRef::boundary((string) $risk['most_relevant_trust_boundary']);
        }
        if (!empty($risk['most_relevant_data_asset'])) {
            return SubjectRef::dataAsset((string) $risk['most_relevant_data_asset']);
        }

        return SubjectRef::model();
    }
}
