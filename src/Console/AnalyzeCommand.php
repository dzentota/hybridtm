<?php
declare(strict_types=1);
namespace HybridTM\Console;

use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\Finding;
use HybridTM\Analysis\RuleEngine;
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
 * SARIF output (T-10.1) is not implemented here — only `table` and `json`.
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
            ->addOption('kb', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Knowledge-base directory (repeatable, later overrides earlier)', [])
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: table or json', 'table')
            ->addOption('min-severity', null, InputOption::VALUE_REQUIRED, 'Only return findings at or above this severity', 'low')
            ->addOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Exit non-zero if any finding reaches this severity (e.g. "high")')
            ->addOption('include-suppressed', null, InputOption::VALUE_NONE, 'Keep findings resolved by riskTracking instead of dropping them');
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
        if (!in_array($format, ['table', 'json'], true)) {
            $io->error("Unsupported --format: {$format} (expected 'table' or 'json')");
            return Command::FAILURE;
        }

        /** @var list<string> $kbPaths */
        $kbPaths = (array) $input->getOption('kb');
        $kb = $kbPaths === [] ? new InMemoryKnowledgeBase([], 'empty') : (new YamlKbLoader())->load($kbPaths);

        $result = (new RuleEngine())->analyze($model, $kb, new AnalysisOptions(
            minSeverity: $minSeverity,
            includeSuppressed: (bool) $input->getOption('include-suppressed'),
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
        } else {
            $this->renderTable($io, $result->findings);
        }

        if ($failOn !== null) {
            foreach ($result->findings as $finding) {
                if ($finding->severity->isAtLeast($failOn)) {
                    return Command::FAILURE;
                }
            }
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
}
