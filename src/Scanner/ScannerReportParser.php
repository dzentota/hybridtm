<?php

declare(strict_types=1);

namespace HybridTM\Scanner;

/**
 * Parses scanner-native JSON reports into normalized ScannerFindings
 * (T-10.8). Each parser handles exactly one tool's native output shape —
 * no attempt to unify the very different upstream schemas before this
 * boundary, since the whole point is to absorb that per-tool variance
 * here and expose one clean shape to everything downstream.
 */
final class ScannerReportParser
{
    public const TOOLS = ['checkov', 'trivy', 'sonarqube'];

    /**
     * @return list<ScannerFinding>
     * @throws \InvalidArgumentException if $tool is unrecognized
     * @throws \JsonException if the report is not valid JSON
     */
    public function parse(string $tool, string $json): array
    {
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        return match ($tool) {
            'checkov' => $this->parseCheckov($data),
            'trivy' => $this->parseTrivy($data),
            'sonarqube' => $this->parseSonarQube($data),
            default => throw new \InvalidArgumentException("Unknown scanner tool \"{$tool}\". Supported: " . implode(', ', self::TOOLS)),
        };
    }

    /**
     * @param array<string, mixed> $data
     * @return list<ScannerFinding>
     */
    private function parseCheckov(array $data): array
    {
        $findings = [];
        $results = (array) ($data['results'] ?? $data);

        foreach ((array) ($results['passed_checks'] ?? []) as $check) {
            $findings[] = new ScannerFinding('checkov', (string) $check['check_id'], true, (string) ($check['resource'] ?? ''));
        }
        foreach ((array) ($results['failed_checks'] ?? []) as $check) {
            $findings[] = new ScannerFinding('checkov', (string) $check['check_id'], false, (string) ($check['resource'] ?? ''));
        }

        return $findings;
    }

    /**
     * @param array<string, mixed> $data
     * @return list<ScannerFinding>
     */
    private function parseTrivy(array $data): array
    {
        $findings = [];

        foreach ((array) ($data['Results'] ?? []) as $result) {
            $target = (string) ($result['Target'] ?? '');
            foreach ((array) ($result['Misconfigurations'] ?? []) as $m) {
                $status = strtoupper((string) ($m['Status'] ?? ''));
                if (!\in_array($status, ['PASS', 'FAIL'], true)) {
                    continue;
                }
                $findings[] = new ScannerFinding('trivy', (string) $m['ID'], $status === 'PASS', $target);
            }
        }

        return $findings;
    }

    /**
     * @param array<string, mixed> $data
     * @return list<ScannerFinding>
     */
    private function parseSonarQube(array $data): array
    {
        $findings = [];

        foreach ((array) ($data['issues'] ?? []) as $issue) {
            $status = strtoupper((string) ($issue['status'] ?? ''));
            // An issue that's RESOLVED/CLOSED means the underlying control now
            // holds; anything still OPEN/CONFIRMED/REOPENED means it doesn't.
            $passed = \in_array($status, ['RESOLVED', 'CLOSED'], true);
            $findings[] = new ScannerFinding('sonarqube', (string) $issue['rule'], $passed, (string) ($issue['component'] ?? ''));
        }

        return $findings;
    }
}
