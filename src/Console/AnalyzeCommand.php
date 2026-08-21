<?php

declare(strict_types=1);

namespace HybridTM\Console;

use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\Finding;
use HybridTM\Analysis\MitigationIndex;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Analysis\StoryCoverage;
use HybridTM\Codec\SarifCodec;
use HybridTM\Compiler\AstScanner;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Severity;
use HybridTM\Kb\InMemoryKnowledgeBase;
use HybridTM\Kb\YamlKbLoader;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * CLI entry point for the Rule Engine (T-3.11): `hybridtm analyze`.
 *
 * `--fail-on` is deliberately independent from `--min-severity`:
 * `--min-severity` controls what's returned/displayed at all,
 * `--fail-on` only decides the process exit code, so a CI pipeline can
 * show every finding while gating on just the severe ones.
 *
 * `--source` scans PHP for #[Mitigation] / #[AbuserStory] so
 * `hasMitigationFor` and story coverage work.
 *
 * `--format sarif` (T-10.1) exports via HybridTM\Codec\SarifCodec, for
 * GitHub Advanced Security and other SARIF-consuming code-scanning UIs.
 */
#[AsCommand(
    name: 'analyze',
    description: 'Run the HybridTM rule engine against a threat model.',
)]
final class AnalyzeCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('infra', null, InputOption::VALUE_REQUIRED, 'Path to the infrastructure DSL file', 'threat-model.php')
            ->addOption('source', null, InputOption::VALUE_REQUIRED, 'Source directory to scan for #[Mitigation]/#[AbuserStory]')
            ->addOption('kb', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Knowledge-base directory (repeatable, later overrides earlier)', [])
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: table or json', 'table')
            ->addOption('min-severity', null, InputOption::VALUE_REQUIRED, 'Only return findings at or above this severity', 'low')
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Exit non-zero if any finding reaches this severity (e.g. "high")')
            ->addOption('include-suppressed', null, InputOption::VALUE_NONE, 'Keep findings resolved by riskTracking instead of dropping them')
            ->addOption('check-stories', null, InputOption::VALUE_NONE, 'Always compute Abuser Story coverage (also runs when the model has abuse cases)')
            ->addOption('fail-on-uncovered-stories', null, InputOption::VALUE_NONE, 'Exit non-zero if any Abuser Story is uncovered or partial');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $infraPath = (string) $input->getOption('infra');
        if (!file_exists($infraPath)) {
            $io->error("DSL file not found: {$infraPath}");
            return Command::FAILURE;
        }

        $model = require $infraPath;
        if (!($model instanceof ThreatModel)) {
            $io->error('The DSL file must return a HybridTM\DSL\ThreatModel instance.');
            return Command::FAILURE;
        }

        $minSeverity = Severity::tryFrom(strtolower((string) $input->getOption('min-severity')));
        if ($minSeverity === null) {
            $io->error('Invalid --min-severity value: ' . $input->getOption('min-severity'));
            return Command::FAILURE;
        }

        $failOnOption = $input->getOption('fail-on');
        $failOn = $failOnOption !== null ? Severity::tryFrom(strtolower((string) $failOnOption)) : null;
        if ($failOnOption !== null && $failOn === null) {
            $io->error('Invalid --fail-on value: ' . $failOnOption);
            return Command::FAILURE;
        }

        $format = (string) $input->getOption('format');
        if (!in_array($format, ['table', 'json', 'sarif'], true)) {
            $io->error("Unsupported --format: {$format} (expected 'table', 'json', or 'sarif')");
            return Command::FAILURE;
        }

        /** @var list<string> $kbPaths */
        $kbPaths = (array) $input->getOption('kb');
        $kb = $kbPaths === [] ? new InMemoryKnowledgeBase([], 'empty') : (new YamlKbLoader())->load($kbPaths);

        $mitigations = null;
        $abuserStoryRefs = [];
        $sourcePath = $input->getOption('source');
        if ($sourcePath !== null && $sourcePath !== '') {
            if (!is_dir((string) $sourcePath)) {
                $io->error("Source directory not found: {$sourcePath}");
                return Command::FAILURE;
            }
            $ast = (new AstScanner())->scan((string) $sourcePath);
            $mitigations = MitigationIndex::fromDiscoveries($ast->mitigations);
            $abuserStoryRefs = $ast->abuserStoryRefs;
            foreach ($ast->warnings as $warning) {
                $io->warning($warning);
            }
        }

        $result = (new RuleEngine())->analyze($model, $kb, new AnalysisOptions(
            minSeverity: $minSeverity,
            includeSuppressed: (bool) $input->getOption('include-suppressed'),
            mitigations: $mitigations,
            abuserStoryRefs: $abuserStoryRefs,
            checkStories: (bool) $input->getOption('check-stories'),
            failOnUncoveredStories: (bool) $input->getOption('fail-on-uncovered-stories'),
        ));

        if ($result->validation->hasErrors()) {
            $io->error('Model validation failed — fix these before analysis can run:');
            foreach ($result->validation->all() as $issue) {
                $io->writeln("  [{$issue->severity->value}] {$issue->code}: {$issue->message}");
            }
            return Command::FAILURE;
        }

        if ($format === 'json') {
            $output->writeln((string) json_encode($result, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        } elseif ($format === 'sarif') {
            $sarif = (new SarifCodec())->export($result);
            $output->writeln((string) json_encode($sarif, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        } else {
            $this->renderTable($io, $result->findings);
            $this->renderStoryCoverage($io, $result->storyCoverage);
        }

        if ($failOn !== null) {
            foreach ($result->findings as $finding) {
                if ($finding->severity->isAtLeast($failOn)) {
                    return Command::FAILURE;
                }
            }
        }

        if ((bool) $input->getOption('fail-on-uncovered-stories') && $result->hasUncoveredStories()) {
            $io->error('One or more Abuser Stories are uncovered or only partially mitigated.');
            return Command::FAILURE;
        }

        return Command::SUCCESS;
    }

    /** @param list<Finding> $findings */
    private function renderTable(SymfonyStyle $io, array $findings): void
    {
        if ($findings === []) {
            $io->success('No findings.');
            return;
        }

        $io->table(
            ['Severity', 'Threat', 'Subject', 'Title'],
            array_map(
                static fn (Finding $f): array => [
                    $f->severity->value,
                    $f->threatId,
                    (string) $f->subject,
                    $f->title,
                ],
                $findings,
            ),
        );
    }

    /** @param list<StoryCoverage> $coverage */
    private function renderStoryCoverage(SymfonyStyle $io, array $coverage): void
    {
        if ($coverage === []) {
            return;
        }

        $io->section('Abuser Story coverage');
        $io->table(
            ['Story', 'Status', 'Covered', 'Missing', 'Issues'],
            array_map(
                static fn (StoryCoverage $c): array => [
                    $c->storyId,
                    $c->status->value,
                    implode(', ', $c->coveredCwes) ?: '—',
                    implode(', ', $c->missingCwes) ?: '—',
                    implode('; ', $c->issues) ?: '—',
                ],
                $coverage,
            ),
        );
    }
}
