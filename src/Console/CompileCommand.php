<?php
declare(strict_types=1);
namespace HybridTM\Console;

use HybridTM\Compiler\AstScanner;
use HybridTM\Compiler\Linker;
use HybridTM\DSL\ThreatModel;
use HybridTM\Yaml\ThreagileSerializer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'compile',
    description: 'Compile PHP DSL + code attributes into a Threagile YAML threat model.',
)]
final class CompileCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('infra', null, InputOption::VALUE_REQUIRED, 'Path to the infrastructure DSL file', 'threat-model.php')
            ->addOption('source', null, InputOption::VALUE_REQUIRED, 'Source directory to scan for #[DataFlow] attributes', 'src/')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Output path for Threagile YAML', 'threagile.yaml');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('HybridTM → Threagile Compiler');

        $infraPath = (string) $input->getOption('infra');
        $srcPath   = (string) $input->getOption('source');
        $outPath   = (string) $input->getOption('out');

        $io->section('Step 1 — Loading infrastructure DSL');
        if (!file_exists($infraPath)) {
            $io->error("DSL file not found: {$infraPath}");
            return Command::FAILURE;
        }

        $model = require $infraPath;
        if (!($model instanceof ThreatModel)) {
            $io->error('The DSL file must return a HybridTM\DSL\ThreatModel instance.');
            return Command::FAILURE;
        }

        $io->success(sprintf(
            "Loaded '%s': %d technical assets, %d data assets, %d trust boundaries.",
            $model->title,
            count($model->getTechnicalAssets()),
            count($model->getDataAssets()),
            count($model->getTrustBoundaries()),
        ));

        $io->section('Step 2 — Scanning source for #[DataFlow] attributes');
        if (!is_dir($srcPath)) {
            $io->error("Source directory not found: {$srcPath}");
            return Command::FAILURE;
        }

        $scanner = new AstScanner();
        $ast = $scanner->scan($srcPath);

        foreach ($ast->warnings as $warning) {
            $io->writeln("  ⚠  {$warning}");
        }

        $io->success(sprintf(
            'AST scan complete: %d data flows, %d mitigations, %d processes-data annotations.',
            count($ast->dataFlows),
            count($ast->mitigations),
            count($ast->processesData),
        ));

        $io->section('Step 3 — Linking and validating cross-references');

        $linker = new Linker();
        try {
            $linker->link($model, $ast);
        } catch (\RuntimeException $e) {
            $io->error('Validation failed: ' . $e->getMessage());
            return Command::FAILURE;
        }

        foreach ($linker->getWarnings() as $warning) {
            $io->writeln("  ⚠  {$warning}");
        }

        $io->success('All cross-references validated.');

        $io->section('Step 4 — Serializing to Threagile YAML');

        $yaml = (new ThreagileSerializer())->serialize($model);
        if (file_put_contents($outPath, $yaml) === false) {
            $io->error("Failed to write output: {$outPath}");
            return Command::FAILURE;
        }

        $io->success("Threagile YAML written to: {$outPath}");

        $totalLinks = array_sum(array_map(fn($a) => count($a->communicationLinks), $model->getTechnicalAssets()));
        $io->table(
            ['Metric', 'Count'],
            [
                ['Technical assets', count($model->getTechnicalAssets())],
                ['Data assets', count($model->getDataAssets())],
                ['Trust boundaries', count($model->getTrustBoundaries())],
                ['Communication links (total)', $totalLinks],
                ['DataFlow annotations', count($ast->dataFlows)],
                ['Mitigation annotations', count($ast->mitigations)],
            ],
        );

        return Command::SUCCESS;
    }
}
