<?php
declare(strict_types=1);
namespace HybridTM\Console;

use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Codec\PhpDslWriter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/** `hybridtm import`: canonical JSON -> threat-model.php (T-4.10). */
#[AsCommand(
    name: 'import',
    description: 'Import a canonical JSON model into a threat-model.php file.',
)]
final class ImportCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('in', null, InputOption::VALUE_REQUIRED, 'Path to the canonical JSON model', 'model.json')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Output path for the generated DSL file', 'threat-model.php');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $inPath = (string) $input->getOption('in');
        if (!file_exists($inPath)) {
            $io->error("JSON model not found: {$inPath}");
            return Command::FAILURE;
        }

        $contents = file_get_contents($inPath);
        $data = $contents !== false ? json_decode($contents, true) : null;
        if (!is_array($data)) {
            $io->error("Could not parse '{$inPath}' as JSON.");
            return Command::FAILURE;
        }

        $model = (new ModelJsonCodec())->decode($data);
        $code = (new PhpDslWriter())->write($model);

        $outPath = (string) $input->getOption('out');
        if (file_put_contents($outPath, $code) === false) {
            $io->error("Failed to write output: {$outPath}");
            return Command::FAILURE;
        }

        $io->success("threat-model.php written to: {$outPath}");
        return Command::SUCCESS;
    }
}
