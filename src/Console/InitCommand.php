<?php

declare(strict_types=1);

namespace HybridTM\Console;

use HybridTM\Codec\PhpDslWriter;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
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
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\Question;

#[AsCommand(
    name:        'init',
    description: 'Interactive wizard to scaffold a threat-model.php file.',
)]
final class InitCommand extends Command
{
    // ── Collected state ───────────────────────────────────────────────────────
    private string $modelTitle = '';
    private string $modelDescription = '';
    private string $modelAuthor = '';
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
    private const C_BRAND = 'bright-cyan';
    private const C_ACCENT = 'bright-magenta';
    private const C_SUCCESS = 'bright-green';
    private const C_WARN = 'bright-yellow';
    private const C_DIM = 'gray';
    private const C_WHITE = 'bright-white';

    protected function configure(): void
    {
        $this->addOption(
            'out',
            'o',
            InputOption::VALUE_REQUIRED,
            'Output path for the generated threat-model.php',
            'threat-model.php',
        );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->output = $output;
        $this->input = $input;
        $questionHelper = $this->getHelper('question');
        if (!$questionHelper instanceof QuestionHelper) {
            throw new \RuntimeException('Expected the "question" helper to be a QuestionHelper instance.');
        }
        $this->questionHelper = $questionHelper;

        $this->registerStyles($output);
        $this->printLogo();
        $this->printWelcome();

        // ── Phase 1: Project metadata ─────────────────────────────────────
        $this->printPhaseHeader(1, 'Project Metadata');
        $this->askProjectMetadata();
        $this->printSummaryBox('Project', [
            'Title' => $this->modelTitle,
            'Author' => $this->modelAuthor,
            'Criticality' => $this->modelCriticality,
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
        $this->output->writeln('        <accent>│</>  <white>  ⚡ Threat Model Wizard</white>' . str_repeat(' ', 43) . '<accent>│</>');
        $this->output->writeln('        <accent>│</>  <dim>  Build your threat-model.php interactively</dim>' . str_repeat(' ', 23) . '<accent>│</>');
        $this->output->writeln('        <accent>│</>  <dim>  Powered by HybridTM — PHP Threat Modeling Framework</dim>' . str_repeat(' ', 12) . '<accent>│</>');
        $this->output->writeln("        <accent>╰{$border}╯</>");
        $this->output->writeln('');
    }

    private function printPhaseHeader(int $phase, string $title): void
    {
        $this->br();
        $width = 64;
        $inner = "  ◆  Phase {$phase}: {$title}  ";
        $pad = max(0, $width - mb_strlen($inner));
        $line = str_repeat('─', $width);

        $this->output->writeln("  <accent>┌{$line}┐</>");
        $this->output->writeln("  <accent>│</><white>{$inner}</>" . str_repeat(' ', $pad) . '<accent>│</>');
        $this->output->writeln("  <accent>└{$line}┘</>");
        $this->br();
    }

    private function printHint(string $text): void
    {
        $this->output->writeln("  <dim>💡 {$text}</>");
        $this->br();
    }

    /**
     * @param array<string, string> $rows
     */
    private function printSummaryBox(string $title, array $rows): void
    {
        $this->br();
        $maxKey = max([0, ...array_map('mb_strlen', array_keys($rows))]);
        $maxVal = max([0, ...array_map('mb_strlen', array_values($rows))]);
        $inner = $maxKey + $maxVal + 7;
        $width = max($inner, mb_strlen($title) + 4);
        $line = str_repeat('─', $width);

        $this->output->writeln("  <success>┌{$line}┐</>");
        $titlePad = max(0, $width - mb_strlen($title) - 2);
        $this->output->writeln("  <success>│</> <white> {$title}</>" . str_repeat(' ', $titlePad) . '<success>│</>');
        $this->output->writeln("  <success>├{$line}┤</>");
        foreach ($rows as $key => $value) {
            $kPad = max(0, $maxKey - mb_strlen($key));
            $vPad = max(0, $width - $maxKey - mb_strlen($value) - 6);
            $this->output->writeln("  <success>│</>  <dim>{$key}</>" . str_repeat(' ', $kPad) . " : <white>{$value}</>" . str_repeat(' ', $vPad) . ' <success>│</>');
        }
        $this->output->writeln("  <success>└{$line}┘</>");
    }

    /**
     * @param array<string, string> $props
     */
    private function printAssetCard(string $emoji, string $id, array $props): void
    {
        $width = 60;
        $line = str_repeat('─', $width);
        $title = "  {$emoji}  {$id}";
        $titlePad = max(0, $width - mb_strlen($title));

        $this->output->writeln("  <brand>┌{$line}┐</>");
        $this->output->writeln("  <brand>│</><white>{$title}</>" . str_repeat(' ', $titlePad) . '<brand>│</>');
        $this->output->writeln("  <brand>├{$line}┤</>");
        foreach ($props as $key => $value) {
            $entry = "  {$key}: {$value}";
            $pad = max(0, $width - mb_strlen($entry));
            $this->output->writeln("  <brand>│</> <dim>{$entry}</>" . str_repeat(' ', $pad - 1) . '<brand>│</>');
        }
        $this->output->writeln("  <brand>└{$line}┘</>");
    }

    private function printSuccessPanel(string $outPath): void
    {
        $width = 64;
        $line = str_repeat('═', $width);

        $this->output->writeln("  <success>╔{$line}╗</>");
        $this->output->writeln('  <success>║</>  <white>  ✅  Threat model generated successfully!</white>' . str_repeat(' ', 19) . '<success>║</>');
        $this->output->writeln('  <success>╟' . str_repeat('─', $width) . '╢</>');

        $fileLine = "     📄  {$outPath}";
        $filePad = max(0, $width - mb_strlen($fileLine));
        $this->output->writeln("  <success>║</><brand>{$fileLine}</>" . str_repeat(' ', $filePad) . '<success>║</>');

        $this->output->writeln('  <success>║</>' . str_repeat(' ', $width) . '<success>║</>');

        $nextLine = '     Next steps:';
        $nextPad = max(0, $width - mb_strlen($nextLine));
        $this->output->writeln("  <success>║</><white>{$nextLine}</>" . str_repeat(' ', $nextPad) . '<success>║</>');

        $steps = [
            '  1. Review and customise the generated file',
            '  2. Add #[DataFlow] attributes to your source code',
            '  3. Run:  php bin/hybridtm compile',
        ];
        foreach ($steps as $step) {
            $pad = max(0, $width - mb_strlen("     {$step}"));
            $this->output->writeln("  <success>║</>  <dim>   {$step}</>" . str_repeat(' ', $pad) . '<success>║</>');
        }

        $this->output->writeln('  <success>║</>' . str_repeat(' ', $width) . '<success>║</>');
        $this->output->writeln("  <success>╚{$line}╝</>");
        $this->br();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Interactive Question Flows
    // ══════════════════════════════════════════════════════════════════════════

    private function askProjectMetadata(): void
    {
        $this->modelTitle = $this->askText('Project title', 'My Application');
        $this->modelDescription = $this->askText('Description', 'Threat model for ' . $this->modelTitle);
        $this->modelAuthor = $this->askText('Author / team name', 'Security Team');
        $this->modelCriticality = $this->askEnum('Business criticality', BusinessCriticality::class);
    }

    // ── Data Assets ───────────────────────────────────────────────────────────

    private function askDataAssets(): void
    {
        do {
            $asset = $this->askOneDataAsset();
            $this->dataAssets[] = $asset;

            $this->printAssetCard('📦', $asset['id'], [
                'Name' => $asset['name'],
                'Confidentiality' => $asset['confidentiality'],
                'Integrity' => $asset['integrity'],
                'Availability' => $asset['availability'],
            ]);
        } while ($this->askConfirm('Add another data asset?'));
    }

    /**
     * @return array{id: string, name: string, desc: string, confidentiality: string, integrity: string, availability: string, origin: string, quantity: string}
     */
    private function askOneDataAsset(): array
    {
        $id = $this->askSlug('Data asset ID (kebab-case)', 'customer-pii');
        $name = $this->askText('Human-readable name', $this->humanize($id));
        $desc = $this->askText('Description', '');

        $this->output->writeln('  <accent>  ── CIA Rating ──</>');
        $confidentiality = $this->askEnum('Confidentiality', Confidentiality::class);
        $integrity = $this->askEnum('Integrity', Integrity::class);
        $availability = $this->askEnum('Availability', Availability::class);
        $origin = $this->askEnum('Data origin', DataOrigin::class);
        $quantity = $this->askEnum('Quantity', Quantity::class);

        return compact('id', 'name', 'desc', 'confidentiality', 'integrity', 'availability', 'origin', 'quantity');
    }

    // ── Technical Assets ──────────────────────────────────────────────────────

    private function askTechnicalAssets(): void
    {
        do {
            $asset = $this->askOneTechnicalAsset();
            $this->technicalAssets[] = $asset;

            $this->printAssetCard('🖥️', $asset['id'], [
                'Name' => $asset['name'],
                'Type' => $asset['type'],
                'Technology' => $asset['technology'],
                'Machine' => $asset['machine'],
                'Internet' => $asset['internet'] ? 'yes' : 'no',
            ]);
        } while ($this->askConfirm('Add another technical asset?'));
    }

    /**
     * @return array{id: string, name: string, desc: string, type: string, technology: string, machine: string, size: string, internet: bool, encryption: string, confidentiality: string, integrity: string, availability: string, processedData: list<string>, storedData: list<string>}
     */
    private function askOneTechnicalAsset(): array
    {
        $id = $this->askSlug('Technical asset ID (kebab-case)', 'web-app');
        $name = $this->askText('Human-readable name', $this->humanize($id));
        $desc = $this->askText('Description', '');

        $type = $this->askEnum('Asset type', AssetType::class);
        $technology = $this->askEnum('Technology', Technology::class);
        $machine = $this->askEnum('Machine type', Machine::class);
        $size = $this->askEnum('Size', Size::class);
        $internet = $this->askConfirm('Exposed to the internet?', false);
        $encryption = $this->askEnum('Encryption at rest', Encryption::class);

        $this->output->writeln('  <accent>  ── CIA Rating ──</>');
        $confidentiality = $this->askEnum('Confidentiality', Confidentiality::class);
        $integrity = $this->askEnum('Integrity', Integrity::class);
        $availability = $this->askEnum('Availability', Availability::class);

        // Link data assets
        $processedData = [];
        $storedData = [];
        if ($this->dataAssets !== [] && $this->askConfirm('Link data assets to this component?')) {
            $ids = array_column($this->dataAssets, 'id');
            $processedData = $this->askMultiSelect('Data assets processed', $ids);
            $storedData = $this->askMultiSelect('Data assets stored', $ids);
        }

        return compact(
            'id',
            'name',
            'desc',
            'type',
            'technology',
            'machine',
            'size',
            'internet',
            'encryption',
            'confidentiality',
            'integrity',
            'availability',
            'processedData',
            'storedData',
        );
    }

    // ── Trust Boundaries ──────────────────────────────────────────────────────

    private function askTrustBoundaries(): void
    {
        do {
            $boundary = $this->askOneTrustBoundary();
            $this->trustBoundaries[] = $boundary;

            $this->printAssetCard('🛡️', $boundary['id'], [
                'Name' => $boundary['name'],
                'Type' => $boundary['type'],
                'Assets' => implode(', ', $boundary['assets']),
            ]);
        } while ($this->askConfirm('Add another trust boundary?'));
    }

    /**
     * @return array{id: string, name: string, desc: string, type: string, assets: list<string>}
     */
    private function askOneTrustBoundary(): array
    {
        $id = $this->askSlug('Trust boundary ID', 'internal-vpc');
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
                'Protocol' => $link['protocol'],
                'Authentication' => $link['authentication'],
                'Authorization' => $link['authorization'],
            ]);
        } while ($this->askConfirm('Add another communication link?'));
    }

    /**
     * @return array{source: string, target: string, protocol: string, authentication: string, authorization: string, desc: string, sentData: list<string>, receivedData: list<string>}
     */
    private function askOneCommunicationLink(): array
    {
        $assetIds = array_column($this->technicalAssets, 'id');

        $source = $this->askChoice('Source asset', $assetIds);
        $remaining = array_values(array_diff($assetIds, [$source]));
        $target = $this->askChoice('Target asset', $remaining);

        $protocol = $this->askEnum('Protocol', Protocol::class);
        $authentication = $this->askEnum('Authentication', Authentication::class);
        $authorization = $this->askEnum('Authorization', Authorization::class);
        $desc = $this->askText('Description', '');

        $sentData = [];
        $receivedData = [];
        if ($this->dataAssets !== [] && $this->askConfirm('Attach data assets to this link?')) {
            $ids = array_column($this->dataAssets, 'id');
            $sentData = $this->askMultiSelect('Data sent', $ids);
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
        $cases = $enumClass::cases();
        $values = array_map(fn ($c) => $c->value, $cases);

        $q = new ChoiceQuestion(
            $this->promptLabel($label, $values[0] ?? ''),
            $values,
            0,
        );
        $q->setErrorMessage('Invalid selection: %s');

        return (string) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    /**
     * @param list<string> $options
     */
    private function askChoice(string $label, array $options): string
    {
        $q = new ChoiceQuestion($this->promptLabel($label), $options, 0);
        return (string) $this->questionHelper->ask($this->input, $this->output, $q);
    }

    /**
     * @param list<string> $options
     * @return list<string>
     */
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
        $answer = $this->questionHelper->ask($this->input, $this->output, $q);

        $selected = [];
        foreach ((array) $answer as $value) {
            $selected[] = (string) $value;
        }
        return $selected;
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

    /**
     * Builds a real ThreatModel from the wizard's collected answers, then
     * delegates code generation to PhpDslWriter (T-4.2) — the same
     * deterministic writer used by `hybridtm export`, rather than the ad-hoc
     * string-building this method used to do itself. A header comment (with
     * the wizard's own description and a generation timestamp — wall-clock
     * input that PhpDslWriter's own output deliberately never depends on)
     * is prepended separately, so PhpDslWriter's determinism contract stays
     * intact for every other caller.
     */
    private function generatePhp(): string
    {
        $model = $this->buildModel();
        $body = (new PhpDslWriter())->write($model);
        // PhpDslWriter's output starts with "<?php\ndeclare(strict_types=1);\n";
        // splice the header comment in right after those two lines.
        [$prologue, $rest] = explode("\n\n", $body, 2);

        return $prologue . "\n"
            . "/**\n"
            . " * HybridTM — {$this->modelTitle}\n"
            . " *\n"
            . " * {$this->modelDescription}\n"
            . " *\n"
            . " * Generated by: php bin/hybridtm init\n"
            . ' * Date: ' . date('Y-m-d') . "\n"
            . " */\n\n"
            . $rest;
    }

    private function buildModel(): ThreatModel
    {
        $model = new ThreatModel($this->modelTitle);
        $model->description = $this->modelDescription;
        $model->author = $this->modelAuthor;
        // Matches the wizard's historical output: the generated file is
        // stamped with its creation date. This wall-clock read belongs
        // here, at the CLI orchestration layer — not inside PhpDslWriter,
        // which must stay deterministic for every other caller.
        $model->date = date('Y-m-d');
        $model->businessCriticality = BusinessCriticality::from($this->modelCriticality);

        foreach ($this->dataAssets as $da) {
            $asset = new DataAsset($da['id'], $da['name']);
            $asset->description = $da['desc'];
            $asset->confidentiality = Confidentiality::from($da['confidentiality']);
            $asset->integrity = Integrity::from($da['integrity']);
            $asset->availability = Availability::from($da['availability']);
            $asset->origin = DataOrigin::from($da['origin']);
            $asset->quantity = Quantity::from($da['quantity']);
            $model->addDataAsset($asset);
        }

        foreach ($this->technicalAssets as $ta) {
            $asset = new TechnicalAsset($ta['id'], $ta['name']);
            $asset->description = $ta['desc'];
            $asset->type = AssetType::from($ta['type']);
            $asset->technology = Technology::from($ta['technology']);
            $asset->machine = Machine::from($ta['machine']);
            $asset->size = Size::from($ta['size']);
            $asset->internet = $ta['internet'];
            $asset->encryption = Encryption::from($ta['encryption']);
            $asset->confidentiality = Confidentiality::from($ta['confidentiality']);
            $asset->integrity = Integrity::from($ta['integrity']);
            $asset->availability = Availability::from($ta['availability']);
            $asset->dataAssetsProcessed = $ta['processedData'];
            $asset->dataAssetsStored = $ta['storedData'];
            $model->addTechnicalAsset($asset);
        }

        foreach ($this->communicationLinks as $cl) {
            $source = $model->getTechnicalAsset($cl['source']);
            if ($source === null) {
                throw new \RuntimeException("Unknown source technical asset: {$cl['source']}");
            }
            $link = $source->communicatesTo(
                targetId: $cl['target'],
                protocol: Protocol::from($cl['protocol']),
                authentication: Authentication::from($cl['authentication']),
                authorization: Authorization::from($cl['authorization']),
                description: $cl['desc'],
            );
            $link->dataSent = $cl['sentData'];
            $link->dataReceived = $cl['receivedData'];
        }

        foreach ($this->trustBoundaries as $tb) {
            $boundary = new TrustBoundary($tb['id'], $tb['name'], TrustBoundaryType::from($tb['type']));
            $boundary->description = $tb['desc'];
            if ($tb['assets'] !== []) {
                $boundary->addAssets(...$tb['assets']);
            }
            $model->addTrustBoundary($boundary);
        }

        return $model;
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Utilities
    // ══════════════════════════════════════════════════════════════════════════

    private function registerStyles(OutputInterface $output): void
    {
        $formatter = $output->getFormatter();
        $formatter->setStyle('brand', new OutputFormatterStyle(self::C_BRAND));
        $formatter->setStyle('accent', new OutputFormatterStyle(self::C_ACCENT));
        $formatter->setStyle('success', new OutputFormatterStyle(self::C_SUCCESS));
        $formatter->setStyle('warn', new OutputFormatterStyle(self::C_WARN));
        $formatter->setStyle('dim', new OutputFormatterStyle(self::C_DIM));
        $formatter->setStyle('white', new OutputFormatterStyle(self::C_WHITE));
    }

    private function br(): void
    {
        $this->output->writeln('');
    }

    private function humanize(string $kebab): string
    {
        return ucwords(str_replace('-', ' ', $kebab));
    }
}
