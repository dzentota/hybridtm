<?php

declare(strict_types=1);

namespace HybridTM\Codec;

use HybridTM\Analysis\AnalysisResult;
use HybridTM\Analysis\Finding;
use HybridTM\Enums\Severity;

/**
 * Exports an AnalysisResult as SARIF 2.1.0 (T-10.1), the format GitHub
 * Advanced Security (and most other code-scanning dashboards) ingest.
 * Every distinct threatId becomes one `rules` entry so GitHub's UI can
 * group/dedupe results by rule, and every Finding becomes one `results`
 * entry pointing at its CodeLocation when the AST scanner found one —
 * findings with no code location (most component/flow-scope findings,
 * which describe infrastructure rather than a specific line) point at
 * `threat-model.php` line 1 instead, since SARIF requires at least one
 * physicalLocation per result.
 */
final class SarifCodec
{
    private const SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

    /** @return array<string, mixed> */
    public function export(AnalysisResult $result, string $toolVersion = '0.1.0'): array
    {
        $rules = [];
        $results = [];

        foreach ($result->findings as $finding) {
            $rules[$finding->threatId] ??= $this->rule($finding);
            $results[] = $this->result($finding);
        }

        return [
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'HybridTM',
                            'informationUri' => 'https://hybridtm.dev',
                            'version' => $toolVersion,
                            'rules' => array_values($rules),
                        ],
                    ],
                    'results' => $results,
                ],
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function rule(Finding $finding): array
    {
        $helpUris = array_map(
            static fn (int $cwe): string => "https://cwe.mitre.org/data/definitions/{$cwe}.html",
            $finding->standards->cwe,
        );

        return [
            'id' => $finding->threatId,
            'name' => $finding->threatId,
            'shortDescription' => ['text' => $finding->title],
            'fullDescription' => ['text' => $finding->description],
            'help' => ['text' => $finding->description, 'markdown' => $this->helpMarkdown($finding, $helpUris)],
            'properties' => array_filter([
                'tags' => array_map(static fn ($s) => $s->value, $finding->stride),
                'cwe' => $finding->standards->cwe,
            ]),
            'defaultConfiguration' => ['level' => $this->level($finding->severity)],
        ];
    }

    /** @param list<string> $helpUris @return string */
    private function helpMarkdown(Finding $finding, array $helpUris): string
    {
        $lines = [$finding->description];
        if ($finding->countermeasureIds !== []) {
            $lines[] = "\n**Countermeasures:** " . implode(', ', $finding->countermeasureIds);
        }
        foreach ($helpUris as $uri) {
            $lines[] = "\n- {$uri}";
        }
        return implode('', $lines);
    }

    /** @return array<string, mixed> */
    private function result(Finding $finding): array
    {
        $location = $finding->codeLocation;
        $file = $location !== null ? $location->file : 'threat-model.php';
        $line = $location !== null ? $location->line : 1;

        return [
            'ruleId' => $finding->threatId,
            'level' => $this->level($finding->severity),
            'message' => ['text' => "{$finding->title}: {$finding->description}"],
            'locations' => [
                [
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $file],
                        'region' => ['startLine' => $line],
                    ],
                    'logicalLocations' => [
                        ['fullyQualifiedName' => $finding->subject],
                    ],
                ],
            ],
            'partialFingerprints' => [
                'hybridtmStableId' => $finding->stableId,
            ],
        ];
    }

    private function level(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical, Severity::High => 'error',
            Severity::Elevated, Severity::Medium => 'warning',
            Severity::Low => 'note',
        };
    }
}
