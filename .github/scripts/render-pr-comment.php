<?php
declare(strict_types=1);

/**
 * Renders the PR comment body for the hybridtm-analyze GitHub Action
 * (T-10.7): reads the current run's SARIF and, if a baseline SARIF from
 * the base branch is available, computes which findings are new vs.
 * resolved by comparing `partialFingerprints.hybridtmStableId` sets
 * (SarifCodec stamps that fingerprint on every result specifically so
 * this comparison is possible). No baseline yet (first run on a new
 * base branch) just prints the current summary with no delta section.
 *
 * Usage: php render-pr-comment.php <current.sarif> [<baseline.sarif>]
 */

function loadFindings(string $path): array
{
    if ($path === '' || !is_file($path)) {
        return [];
    }
    $sarif = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    $findings = [];
    foreach ($sarif['runs'][0]['results'] ?? [] as $result) {
        $id = $result['partialFingerprints']['hybridtmStableId'] ?? null;
        if ($id === null) {
            continue;
        }
        $findings[$id] = [
            'ruleId' => $result['ruleId'],
            'level' => $result['level'],
            'message' => $result['message']['text'] ?? '',
        ];
    }
    return $findings;
}

function countByLevel(array $findings): array
{
    $counts = ['error' => 0, 'warning' => 0, 'note' => 0];
    foreach ($findings as $f) {
        $counts[$f['level']] = ($counts[$f['level']] ?? 0) + 1;
    }
    return $counts;
}

$currentPath = $argv[1] ?? null;
$baselinePath = $argv[2] ?? '';

if ($currentPath === null) {
    fwrite(STDERR, "Usage: php render-pr-comment.php <current.sarif> [<baseline.sarif>]\n");
    exit(1);
}

$current = loadFindings($currentPath);
$counts = countByLevel($current);

echo "### HybridTM threat model analysis\n\n";
echo "| Level | Count |\n|---|---|\n";
foreach ($counts as $level => $count) {
    echo "| {$level} | {$count} |\n";
}
echo "\n";

if ($baselinePath === '') {
    echo "_No baseline from the base branch yet — this will show a risk delta on the next run._\n";
    exit(0);
}

$baseline = loadFindings($baselinePath);
$newIds = array_diff(array_keys($current), array_keys($baseline));
$resolvedIds = array_diff(array_keys($baseline), array_keys($current));

echo "#### Delta vs. base branch\n\n";

if ($newIds === [] && $resolvedIds === []) {
    echo "No change in findings.\n";
    exit(0);
}

if ($newIds !== []) {
    echo "**New findings (" . count($newIds) . "):**\n\n";
    foreach ($newIds as $id) {
        echo "- `{$current[$id]['ruleId']}` ({$current[$id]['level']}): {$current[$id]['message']}\n";
    }
    echo "\n";
}

if ($resolvedIds !== []) {
    echo "**Resolved findings (" . count($resolvedIds) . "):**\n\n";
    foreach ($resolvedIds as $id) {
        echo "- `{$baseline[$id]['ruleId']}` ({$baseline[$id]['level']}): {$baseline[$id]['message']}\n";
    }
}
