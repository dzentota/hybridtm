<?php
declare(strict_types=1);
namespace HybridTM\Console;

use HybridTM\Codec\ModelJsonCodec;
use HybridTM\DSL\ThreatModel;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/** `hybridtm export`: threat-model.php -> canonical JSON (T-4.10). */
#[AsCommand(
    name: 'export',
    description: 'Export a threat-model.php file to the canonical JSON model.',
)]
final class ExportCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('infra', null, InputOption::VALUE_REQUIRED, 'Path to the infrastructure DSL file', 'threat-model.php')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Output path for the canonical JSON model', 'model.json')
            ->addOption('kb-version', null, InputOption::VALUE_REQUIRED, 'Knowledge-base version string to stamp into the output (e.g. "kb-core@1.4.0")', '');
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

        $encoded = (new ModelJsonCodec())->encode($model, (string) $input->getOption('kb-version'));
        $json = json_encode($encoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $outPath = (string) $input->getOption('out');
        if (file_put_contents($outPath, $json . "\n") === false) {
            $io->error("Failed to write output: {$outPath}");
            return Command::FAILURE;
        }

        $io->success("Canonical JSON model written to: {$outPath}");
        return Command::SUCCESS;
    }
}
