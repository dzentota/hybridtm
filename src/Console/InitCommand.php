<?php

declare(strict_types=1);

namespace HybridTM\Console;

use HybridTM\Enums\AssetType;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Availability;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\Size;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Helper\QuestionHelper;

#[AsCommand(
    name:        'init',
    description: 'Interactive wizard to scaffold a threat-model.php file.',
)]
final class InitCommand extends Command
{
    // ── Collected state ───────────────────────────────────────────────────────
    private string $modelTitle       = '';
    private string $modelDescription = '';
    private string $modelAuthor      = '';
    private string $modelCriticality = 'important';

    /** @var array<int, array<string, mixed>> */
    private array $dataAssets = [];

    /** @var array<int, array<string, mixed>> */
    private array $technicalAssets = [];

    /** @var array<int, array<string, mixed>> */
    private array $trustBoundaries = [];

    /** @var array<int, array<string, mixed>> */
    private array $communicationLinks = [];

    private OutputInterface $output;
    private QuestionHelper $questionHelper;
    private InputInterface $input;

    // ── Colour palette ────────────────────────────────────────────────────────
    private const C_BRAND   = 'bright-cyan';
    private const C_ACCENT  = 'bright-magenta';
    private const C_SUCCESS = 'bright-green';
    private const C_WARN    = 'bright-yellow';
    private const C_DIM     = 'gray';
    private const C_WHITE   = 'bright-white';

    protected function configure(): void
    {
        $this->addOption(
            'out', 'o', InputOption::VALUE_REQUIRED,
            'Output path for the generated threat-model.php',
            'threat-model.php',
        );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->output         = $output;
        $this->input          = $input;
        $this->questionHelper = $this->getHelper('question');

        $this->registerStyles($output);
        $this->printLogo();
        $this->printWelcome();

        // ── Phase 1: Project metadata ─────────────────────────────────────
        $this->printPhaseHeader(1, 'Project Metadata');
        $this->askProjectMetadata();
        $this->printSummaryBox('Project', [
            'Title'        => $this->modelTitle,
            'Author'       => $this->modelAuthor,
            'Criticality'  => $this->modelCriticality,
        ]);

        // ── Phase 2: Data assets ──────────────────────────────────────────
        $this->printPhaseHeader(2, 'Data Assets');
        $this->printHint('Data assets represent the information your system handles (PII, credentials, tokens, etc.).');
        $this->askDataAssets();

        // ── Phase 3: Technical assets ─────────────────────────────────────
        $this->printPhaseHeader(3, 'Technical Assets');
        $this->printHint('Technical assets are the running components: web apps, APIs, databases, caches, message queues, etc.');
        $this->askTechnicalAssets();

        // ── Phase 4: Trust boundaries ─────────────────────────────────────
        $this->printPhaseHeader(4, 'Trust Boundaries');
        $this->printHint('Trust boundaries group assets by network zone / privilege level (VPC, DMZ, public internet…).');
        $this->askTrustBoundaries();

        // ── Phase 5: Communication links ──────────────────────────────────
        $this->printPhaseHeader(5, 'Communication Links');
        $this->printHint('Define how technical assets talk to each other — protocols, auth, and which data flows across.');
        $this->askCommunicationLinks();

        // ── Generate ──────────────────────────────────────────────────────
        $outPath = (string) $input->getOption('out');
        $this->printPhaseHeader(6, 'Generate');
        $code = $this->generatePhp();
        file_put_contents($outPath, $code);

        $this->br();
        $this->printSuccessPanel($outPath);

        return Command::SUCCESS;
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  ASCII Logo & Banners
    // ══════════════════════════════════════════════════════════════════════════

    private function printLogo(): void
    {
        $logo = <<<'ASCII'

        <brand>  ██╗  ██╗██╗   ██╗██████╗ ██████╗ ██╗██████╗ ████████╗███╗   ███╗</>
        <brand>  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔══██╗╚══██╔══╝████╗ ████║</>
        <brand>  ███████║ ╚████╔╝ ██████╔╝██████╔╝██║██║  ██║   ██║   ██╔████╔██║</>
        <brand>  ██╔══██║  ╚██╔╝  ██╔══██╗██╔══██╗██║██║  ██║   ██║   ██║╚██╔╝██║</>
        <brand>  ██║  ██║   ██║   ██████╔╝██║  ██║██║██████╔╝   ██║   ██║ ╚═╝ ██║</>
        <brand>  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝    ╚═╝   ╚═╝     ╚═╝</>

ASCII;
        $this->output->writeln($logo);
    }

    private function printWelcome(): void
    {
        $width = 68;
        $border = str_repeat('─', $width);

        $this->output->writeln('');
        $this->output->writeln("        <accent>╭{$border}╮</>");
        $this->output->writeln("        <accent>│</>  <white>  ⚡ Threat Model Wizard</white>" . str_repeat(' ', 43) . "<accent>│</>");
        $this->output->writeln("        <accent>│</>  <dim>  Build your threat-model.php interactively</dim>" . str_repeat(' ', 23) . "<accent>│</>");
        $this->output->writeln("        <accent>│</>  <dim>  Powered by HybridTM — PHP Threat Modeling Framework</dim>" . str_repeat(' ', 12) . "<accent>│</>");
        $this->output->writeln("        <accent>╰{$border}╯</>");
        $this->output->writeln('');
    }

    private function printPhaseHeader(int $phase, string $title): void
    {
        $this->br();
        $width = 64;
        $inner = "  ◆  Phase {$phase}: {$title}  ";
        $pad   = max(0, $width - mb_strlen($inner));
        $line  = str_repeat('─', $width);

        $this->output->writeln("  <accent>┌{$line}┐</>");
        $this->output->writeln("  <accent>│</><white>{$inner}</>" . str_repeat(' ', $pad) . "<accent>│</>");
        $this->output->writeln("  <accent>└{$line}┘</>");
        $this->br();
    }

    private function printHint(string $text): void
    {
        $this->output->writeln("  <dim>💡 {$text}</>");
        $this->br();
    }

    private function printSummaryBox(string $title, array $rows): void
    {
        $this->br();
        $maxKey = max(array_map('mb_strlen', array_keys($rows)));
        $maxVal = max(array_map('mb_strlen', array_values($rows)));
        $inner  = $maxKey + $maxVal + 7;
        $width  = max($inner, mb_strlen($title) + 4);
        $line   = str_repeat('─', $width);

        $this->output->writeln("  <success>┌{$line}┐</>");
        $titlePad = max(0, $width - mb_strlen($title) - 2);
        $this->output->writeln("  <success>│</> <white> {$title}</>" . str_repeat(' ', $titlePad) . "<success>│</>");
        $this->output->writeln("  <success>├{$line}┤</>");
        foreach ($rows as $key => $value) {
            $kPad = max(0, $maxKey - mb_strlen($key));
            $vPad = max(0, $width - $maxKey - mb_strlen($value) - 6);
            $this->output->writeln("  <success>│</>  <dim>{$key}</>" . str_repeat(' ', $kPad) . " : <white>{$value}</>" . str_repeat(' ', $vPad) . " <success>│</>");
        }
        $this->output->writeln("  <success>└{$line}┘</>");
    }

    private function printAssetCard(string $emoji, string $id, array $props): void
    {
        $width = 60;
        $line  = str_repeat('─', $width);
        $title = "  {$emoji}  {$id}";
        $titlePad = max(0, $width - mb_strlen($title));

        $this->output->writeln("  <brand>┌{$line}┐</>");
        $this->output->writeln("  <brand>│</><white>{$title}</>" . str_repeat(' ', $titlePad) . "<brand>│</>");
        $this->output->writeln("  <brand>├{$line}┤</>");
        foreach ($props as $key => $value) {
            $entry = "  {$key}: {$value}";
            $pad = max(0, $width - mb_strlen($entry));
            $this->output->writeln("  <brand>│</> <dim>{$entry}</>" . str_repeat(' ', $pad - 1) . "<brand>│</>");
        }
        $this->output->writeln("  <brand>└{$line}┘</>");
    }

    private function printSuccessPanel(string $outPath): void
    {
        $width = 64;
        $line  = str_repeat('═', $width);

        $this->output->writeln("  <success>╔{$line}╗</>");
        $this->output->writeln("  <success>║</>  <white>  ✅  Threat model generated successfully!</white>" . str_repeat(' ', 19) . "<success>║</>");
        $this->output->writeln("  <success>╟" . str_repeat('─', $width) . "╢</>");

        $fileLine = "     📄  {$outPath}";
        $filePad = max(0, $width - mb_strlen($fileLine));
        $this->output->writeln("  <success>║</><brand>{$fileLine}</>" . str_repeat(' ', $filePad) . "<success>║</>");

        $this->output->writeln("  <success>║</>" . str_repeat(' ', $width) . "<success>║</>");

        $nextLine = '     Next steps:';
        $nextPad = max(0, $width - mb_strlen($nextLine));
        $this->output->writeln("  <success>║</><white>{$nextLine}</>" . str_repeat(' ', $nextPad) . "<success>║</>");

        $steps = [
            '  1. Review and customise the generated file',
            '  2. Add #[DataFlow] attributes to your source code',
            '  3. Run:  php bin/hybridtm compile',
        ];
        foreach ($steps as $step) {
            $pad = max(0, $width - mb_strlen("     {$step}"));
            $this->output->writeln("  <success>║</>  <dim>   {$step}</>" . str_repeat(' ', $pad) . "<success>║</>");
        }

        $this->output->writeln("  <success>║</>" . str_repeat(' ', $width) . "<success>║</>");
        $this->output->writeln("  <success>╚{$line}╝</>");
        $this->br();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Interactive Question Flows
    // ══════════════════════════════════════════════════════════════════════════

    private function askProjectMetadata(): void
    {
        $this->modelTitle       = $this->askText('Project title', 'My Application');
        $this->modelDescription = $this->askText('Description', 'Threat model for ' . $this->modelTitle);
        $this->modelAuthor      = $this->askText('Author / team name', 'Security Team');
        $this->modelCriticality = $this->askEnum('Business criticality', BusinessCriticality::class);
    }

    // ── Data Assets ───────────────────────────────────────────────────────────

    private function askDataAssets(): void
    {
        do {
            $asset = $this->askOneDataAsset();
            $this->dataAssets[] = $asset;

            $this->printAssetCard('📦', $asset['id'], [
                'Name'            => $asset['name'],
                'Confidentiality' => $asset['confidentiality'],
                'Integrity'       => $asset['integrity'],
                'Availability'    => $asset['availability'],
            ]);
        } while ($this->askConfirm('Add another data asset?'));
    }

    private function askOneDataAsset(): array
    {
        $id   = $this->askSlug('Data asset ID (kebab-case)', 'customer-pii');
        $name = $this->askText('Human-readable name', $this->humanize($id));
        $desc = $this->askText('Description', '');

        $this->output->writeln("  <accent>  ── CIA Rating ──</>");
        $confidentiality = $this->askEnum('Confidentiality', Confidentiality::class);
        $integrity       = $this->askEnum('Integrity', Integrity::class);
        $availability    = $this->askEnum('Availability', Availability::class);
        $origin          = $this->askEnum('Data origin', DataOrigin::class);
        $quantity         = $this->askEnum('Quantity', Quantity::class);

        return compact('id', 'name', 'desc', 'confidentiality', 'integrity', 'availability', 'origin', 'quantity');
    }

    // ── Technical Assets ──────────────────────────────────────────────────────

    private function askTechnicalAssets(): void
    {
        do {
            $asset = $this->askOneTechnicalAsset();
            $this->technicalAssets[] = $asset;

            $this->printAssetCard('🖥️', $asset['id'], [
                'Name'       => $asset['name'],
                'Type'       => $asset['type'],
                'Technology' => $asset['technology'],
                'Machine'    => $asset['machine'],
                'Internet'   => $asset['internet'] ? 'yes' : 'no',
            ]);
        } while ($this->askConfirm('Add another technical asset?'));
    }

    private function askOneTechnicalAsset(): array
    {
        $id   = $this->askSlug('Technical asset ID (kebab-case)', 'web-app');
        $name = $this->askText('Human-readable name', $this->humanize($id));
        $desc = $this->askText('Description', '');

        $type       = $this->askEnum('Asset type', AssetType::class);
        $technology = $this->askEnum('Technology', Technology::class);
        $machine    = $this->askEnum('Machine type', Machine::class);
        $size       = $this->askEnum('Size', Size::class);
        $internet   = $this->askConfirm('Exposed to the internet?', false);
        $encryption = $this->askEnum('Encryption at rest', Encryption::class);

        $this->output->writeln("  <accent>  ── CIA Rating ──</>");
        $confidentiality = $this->askEnum('Confidentiality', Confidentiality::class);
        $integrity       = $this->askEnum('Integrity', Integrity::class);
        $availability    = $this->askEnum('Availability', Availability::class);

        // Link data assets
        $processedData = [];
        $storedData    = [];
        if ($this->dataAssets !== [] && $this->askConfirm('Link data assets to this component?')) {
            $ids = array_column($this->dataAssets, 'id');
            $processedData = $this->askMultiSelect('Data assets processed', $ids);
            $storedData    = $this->askMultiSelect('Data assets stored', $ids);
        }

        return compact(
            'id', 'name', 'desc', 'type', 'technology', 'machine', 'size',
            'internet', 'encryption', 'confidentiality', 'integrity', 'availability',
            'processedData', 'storedData',
        );
    }

    // ── Trust Boundaries ──────────────────────────────────────────────────────

    private function askTrustBoundaries(): void
    {
        do {
            $boundary = $this->askOneTrustBoundary();
            $this->trustBoundaries[] = $boundary;

            $this->printAssetCard('🛡️', $boundary['id'], [
                'Name'   => $boundary['name'],
                'Type'   => $boundary['type'],
                'Assets' => implode(', ', $boundary['assets']),
            ]);
        } while ($this->askConfirm('Add another trust boundary?'));
    }

    private function askOneTrustBoundary(): array
    {
        $id   = $this->askSlug('Trust boundary ID', 'internal-vpc');
        $name = $this->askText('Human-readable name', $this->humanize($id));
        $desc = $this->askText('Description', '');
        $type = $this->askEnum('Boundary type', TrustBoundaryType::class);

        $assetIds = array_column($this->technicalAssets, 'id');
        $assets = $this->askMultiSelect('Technical assets inside this boundary', $assetIds);

        return compact('id', 'name', 'desc', 'type', 'assets');
    }

    // ── Communication Links ───────────────────────────────────────────────────

    private function askCommunicationLinks(): void
    {
        if (count($this->technicalAssets) < 2) {
            $this->output->writeln('  <warn>⚠ Need at least 2 technical assets to define links. Skipping.</warn>');
            return;
        }

        do {
            $link = $this->askOneCommunicationLink();
            $this->communicationLinks[] = $link;

            $this->printAssetCard('🔗', "{$link['source']} → {$link['target']}", [
                'Protocol'       => $link['protocol'],
                'Authentication' => $link['authentication'],
                'Authorization'  => $link['authorization'],
            ]);
        } while ($this->askConfirm('Add another communication link?'));
    }

    private function askOneCommunicationLink(): array
    {
        $assetIds = array_column($this->technicalAssets, 'id');

        $source = $this->askChoice('Source asset', $assetIds);
        $remaining = array_values(array_diff($assetIds, [$source]));
        $target = $this->askChoice('Target asset', $remaining);

        $protocol       = $this->askEnum('Protocol', Protocol::class);
        $authentication = $this->askEnum('Authentication', Authentication::class);
        $authorization  = $this->askEnum('Authorization', Authorization::class);
        $desc           = $this->askText('Description', '');

        $sentData     = [];
        $receivedData = [];
        if ($this->dataAssets !== [] && $this->askConfirm('Attach data assets to this link?')) {
            $ids = array_column($this->dataAssets, 'id');
            $sentData     = $this->askMultiSelect('Data sent', $ids);
            $receivedData = $this->askMultiSelect('Data received', $ids);
        }

        return compact('source', 'target', 'protocol', 'authentication', 'authorization', 'desc', 'sentData', 'receivedData');
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Question Helpers
    // ══════════════════════════════════════════════════════════════════════════

    private function askText(string $label, string $default = ''): string
    {
        $q = new Question($this->promptLabel($label, $default), $default);
        return (string) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    private function askSlug(string $label, string $default = ''): string
    {
        $q = new Question($this->promptLabel($label, $default), $default);
        $q->setValidator(function (?string $value) {
            $v = trim($value ?? '');
            if ($v === '' || !preg_match('/^[a-z0-9][a-z0-9\-]*$/', $v)) {
                throw new \RuntimeException('Must be non-empty kebab-case (a-z, 0-9, hyphens).');
            }
            return $v;
        });
        return (string) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    /**
     * Presents an enum's cases as a choice list using the string-backed values.
     * Returns the selected enum value string.
     */
    private function askEnum(string $label, string $enumClass): string
    {
        $cases  = $enumClass::cases();
        $values = array_map(fn($c) => $c->value, $cases);

        $q = new ChoiceQuestion(
            $this->promptLabel($label, $values[0] ?? ''),
            $values,
            0,
        );
        $q->setErrorMessage('Invalid selection: %s');

        return (string) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    private function askChoice(string $label, array $options): string
    {
        $q = new ChoiceQuestion($this->promptLabel($label), $options, 0);
        return (string) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    private function askMultiSelect(string $label, array $options): array
    {
        if ($options === []) {
            return [];
        }
        $q = new ChoiceQuestion(
            $this->promptLabel($label, 'comma-separated'),
            $options,
        );
        $q->setMultiselect(true);
        return (array) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    private function askConfirm(string $label, bool $default = true): bool
    {
        $hint = $default ? 'Y/n' : 'y/N';
        $q = new ConfirmationQuestion(
            "  <accent>▸</> <white>{$label}</> <dim>[{$hint}]</> ",
            $default,
        );
        return (bool) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    private function promptLabel(string $label, string $default = ''): string
    {
        $suffix = $default !== '' ? " <dim>[{$default}]</>" : '';
        return "  <accent>▸</> <white>{$label}</>$suffix: ";
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  PHP Code Generator
    // ══════════════════════════════════════════════════════════════════════════

    private function generatePhp(): string
    {
        $lines = [];
        $lines[] = '<?php';
        $lines[] = '/**';
        $lines[] = " * HybridTM — {$this->modelTitle}";
        $lines[] = ' *';
        $lines[] = " * {$this->modelDescription}";
        $lines[] = ' *';
        $lines[] = ' * Generated by: php bin/hybridtm init';
        $lines[] = ' * Date: ' . date('Y-m-d');
        $lines[] = ' */';
        $lines[] = 'declare(strict_types=1);';
        $lines[] = '';
        $lines[] = "require_once __DIR__ . '/vendor/autoload.php';";
        $lines[] = '';

        // Collect used enums
        $usedEnums = $this->collectUsedEnums();
        $lines[] = 'use HybridTM\\DSL\\DataAsset;';
        $lines[] = 'use HybridTM\\DSL\\TechnicalAsset;';
        $lines[] = 'use HybridTM\\DSL\\ThreatModel;';
        $lines[] = 'use HybridTM\\DSL\\TrustBoundary;';
        foreach ($usedEnums as $enum) {
            $lines[] = "use HybridTM\\Enums\\{$enum};";
        }
        $lines[] = '';

        // ── Model metadata ────────────────────────────────────────────────
        $lines[] = '// ── Model metadata ' . str_repeat('─', 58);
        $lines[] = '';
        $title = $this->esc($this->modelTitle);
        $lines[] = "\$model = new ThreatModel('{$title}');";
        $lines[] = "\$model->description         = '{$this->esc($this->modelDescription)}';";
        $lines[] = "\$model->author              = '{$this->esc($this->modelAuthor)}';";
        $lines[] = "\$model->date                = '" . date('Y-m-d') . "';";
        $crit = $this->enumCase(BusinessCriticality::class, $this->modelCriticality);
        $lines[] = "\$model->businessCriticality = BusinessCriticality::{$crit};";
        $lines[] = '';

        // ── Data assets ───────────────────────────────────────────────────
        if ($this->dataAssets !== []) {
            $lines[] = '// ── Data Assets ' . str_repeat('─', 61);
            $lines[] = '';
            foreach ($this->dataAssets as $da) {
                $var = $this->varName($da['id']);
                $lines[] = "\${$var} = new DataAsset('{$da['id']}', '{$this->esc($da['name'])}');";
                if ($da['desc'] !== '') {
                    $lines[] = "\${$var}->description     = '{$this->esc($da['desc'])}';";
                }
                $lines[] = "\${$var}->confidentiality = Confidentiality::{$this->enumCase(Confidentiality::class, $da['confidentiality'])};";
                $lines[] = "\${$var}->integrity       = Integrity::{$this->enumCase(Integrity::class, $da['integrity'])};";
                $lines[] = "\${$var}->availability    = Availability::{$this->enumCase(Availability::class, $da['availability'])};";
                $lines[] = "\${$var}->origin          = DataOrigin::{$this->enumCase(DataOrigin::class, $da['origin'])};";
                $lines[] = "\${$var}->quantity        = Quantity::{$this->enumCase(Quantity::class, $da['quantity'])};";
                $lines[] = "\$model->addDataAsset(\${$var});";
                $lines[] = '';
            }
        }

        // ── Technical assets ──────────────────────────────────────────────
        if ($this->technicalAssets !== []) {
            $lines[] = '// ── Technical Assets ' . str_repeat('─', 56);
            $lines[] = '';
            foreach ($this->technicalAssets as $ta) {
                $var = $this->varName($ta['id']);
                $lines[] = "\${$var} = new TechnicalAsset('{$ta['id']}', '{$this->esc($ta['name'])}');";
                if ($ta['desc'] !== '') {
                    $lines[] = "\${$var}->description          = '{$this->esc($ta['desc'])}';";
                }
                $lines[] = "\${$var}->type                 = AssetType::{$this->enumCase(AssetType::class, $ta['type'])};";
                $lines[] = "\${$var}->technology           = Technology::{$this->enumCase(Technology::class, $ta['technology'])};";
                $lines[] = "\${$var}->machine              = Machine::{$this->enumCase(Machine::class, $ta['machine'])};";
                $lines[] = "\${$var}->size                 = Size::{$this->enumCase(Size::class, $ta['size'])};";
                $lines[] = "\${$var}->internet             = " . ($ta['internet'] ? 'true' : 'false') . ';';
                $lines[] = "\${$var}->encryption           = Encryption::{$this->enumCase(Encryption::class, $ta['encryption'])};";
                $lines[] = "\${$var}->confidentiality      = Confidentiality::{$this->enumCase(Confidentiality::class, $ta['confidentiality'])};";
                $lines[] = "\${$var}->integrity            = Integrity::{$this->enumCase(Integrity::class, $ta['integrity'])};";
                $lines[] = "\${$var}->availability         = Availability::{$this->enumCase(Availability::class, $ta['availability'])};";
                if ($ta['processedData'] !== []) {
                    $arr = "['" . implode("', '", $ta['processedData']) . "']";
                    $lines[] = "\${$var}->dataAssetsProcessed = {$arr};";
                }
                if ($ta['storedData'] !== []) {
                    $arr = "['" . implode("', '", $ta['storedData']) . "']";
                    $lines[] = "\${$var}->dataAssetsStored    = {$arr};";
                }
                $lines[] = "\$model->addTechnicalAsset(\${$var});";
                $lines[] = '';
            }
        }

        // ── Communication links ───────────────────────────────────────────
        if ($this->communicationLinks !== []) {
            $lines[] = '// ── Communication Links ' . str_repeat('─', 53);
            $lines[] = '';
            foreach ($this->communicationLinks as $cl) {
                $srcVar = $this->varName($cl['source']);
                $lines[] = "\${$srcVar}->communicatesTo(";
                $lines[] = "    targetId: '{$cl['target']}',";
                $lines[] = "    protocol: Protocol::{$this->enumCase(Protocol::class, $cl['protocol'])},";
                $lines[] = "    authentication: Authentication::{$this->enumCase(Authentication::class, $cl['authentication'])},";
                $lines[] = "    authorization: Authorization::{$this->enumCase(Authorization::class, $cl['authorization'])},";
                if ($cl['desc'] !== '') {
                    $lines[] = "    description: '{$this->esc($cl['desc'])}',";
                }
                $lines[] = ');';
                $lines[] = '';
            }
        }

        // ── Trust boundaries ──────────────────────────────────────────────
        if ($this->trustBoundaries !== []) {
            $lines[] = '// ── Trust Boundaries ' . str_repeat('─', 56);
            $lines[] = '';
            foreach ($this->trustBoundaries as $tb) {
                $var = $this->varName($tb['id']);
                $lines[] = "\${$var} = new TrustBoundary('{$tb['id']}', '{$this->esc($tb['name'])}', TrustBoundaryType::{$this->enumCase(TrustBoundaryType::class, $tb['type'])});";
                if ($tb['desc'] !== '') {
                    $lines[] = "\${$var}->description = '{$this->esc($tb['desc'])}';";
                }
                if ($tb['assets'] !== []) {
                    $assetList = "'" . implode("', '", $tb['assets']) . "'";
                    $lines[] = "\${$var}->addAssets({$assetList});";
                }
                $lines[] = "\$model->addTrustBoundary(\${$var});";
                $lines[] = '';
            }
        }

        $lines[] = 'return $model;';
        $lines[] = '';

        return implode("\n", $lines);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Utilities
    // ══════════════════════════════════════════════════════════════════════════

    private function registerStyles(OutputInterface $output): void
    {
        $formatter = $output->getFormatter();
        $formatter->setStyle('brand',   new OutputFormatterStyle(self::C_BRAND));
        $formatter->setStyle('accent',  new OutputFormatterStyle(self::C_ACCENT));
        $formatter->setStyle('success', new OutputFormatterStyle(self::C_SUCCESS));
        $formatter->setStyle('warn',    new OutputFormatterStyle(self::C_WARN));
        $formatter->setStyle('dim',     new OutputFormatterStyle(self::C_DIM));
        $formatter->setStyle('white',   new OutputFormatterStyle(self::C_WHITE));
    }

    private function br(): void
    {
        $this->output->writeln('');
    }

    private function esc(string $value): string
    {
        return str_replace("'", "\\'", $value);
    }

    private function varName(string $kebab): string
    {
        return lcfirst(str_replace(' ', '', ucwords(str_replace('-', ' ', $kebab))));
    }

    private function humanize(string $kebab): string
    {
        return ucwords(str_replace('-', ' ', $kebab));
    }

    /** Returns the PHP case name for an enum value string. */
    private function enumCase(string $enumClass, string $value): string
    {
        foreach ($enumClass::cases() as $case) {
            if ($case->value === $value) {
                return $case->name;
            }
        }
        return $enumClass::cases()[0]->name;
    }

    /** @return string[] Enum short class names that are referenced. */
    private function collectUsedEnums(): array
    {
        $enums = ['AssetType', 'Availability', 'BusinessCriticality', 'Confidentiality', 'Integrity'];

        if ($this->dataAssets !== []) {
            $enums[] = 'DataOrigin';
            $enums[] = 'Quantity';
        }
        if ($this->technicalAssets !== []) {
            $enums[] = 'Encryption';
            $enums[] = 'Machine';
            $enums[] = 'Size';
            $enums[] = 'Technology';
        }
        if ($this->communicationLinks !== []) {
            $enums[] = 'Authentication';
            $enums[] = 'Authorization';
            $enums[] = 'Protocol';
        }
        if ($this->trustBoundaries !== []) {
            $enums[] = 'TrustBoundaryType';
        }

        sort($enums);
        return array_unique($enums);
    }
}
