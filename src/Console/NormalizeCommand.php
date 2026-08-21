<?php

declare(strict_types=1);

namespace HybridTM\Console;

use HybridTM\Codec\PhpDslReader;
use HybridTM\Codec\PhpDslWriter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * `hybridtm normalize`: rewrites a hand-written threat-model.php into
 * PhpDslWriter's canonical form (T-4.10) — read via PhpDslReader's AST
 * parse (never `require`, per ADR-08), then written back with
 * PhpDslWriter. Refuses to touch the file if it contains anything outside
 * the recognizable subset (ADR-08): rewriting a non-canonical file would
 * silently drop whatever wasn't recognized, so every unrecognized
 * construct is reported instead and nothing is written.
 */
#[AsCommand(
    name: 'normalize',
    description: 'Rewrite a threat-model.php file into canonical, deterministic form.',
)]
final class NormalizeCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('infra', null, InputOption::VALUE_REQUIRED, 'Path to the infrastructure DSL file', 'threat-model.php')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Output path (defaults to overwriting --infra in place)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $infraPath = (string) $input->getOption('infra');
        if (!file_exists($infraPath)) {
            $io->error("DSL file not found: {$infraPath}");
            return Command::FAILURE;
        }

        $result = (new PhpDslReader())->readFile($infraPath);

        if (!$result->isCanonical()) {
            $io->error("'{$infraPath}' contains constructs outside the recognizable subset (ADR-08) and was not modified:");
            foreach ($result->nonCanonical as $issue) {
                $io->writeln("  {$issue}");
            }
            $io->writeln('');
            $io->writeln('See docs/dsl-subset.md for what is and is not recognized.');
            return Command::FAILURE;
        }

        if ($result->model === null) {
            $io->error("'{$infraPath}' could not be parsed.");
            return Command::FAILURE;
        }

        $code = (new PhpDslWriter())->write($result->model);
        $outPath = (string) ($input->getOption('out') ?: $infraPath);

        if (file_put_contents($outPath, $code) === false) {
            $io->error("Failed to write output: {$outPath}");
            return Command::FAILURE;
        }

        $io->success("Normalized DSL written to: {$outPath}");
        return Command::SUCCESS;
    }
}
