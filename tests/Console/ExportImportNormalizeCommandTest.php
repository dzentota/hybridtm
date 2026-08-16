<?php
declare(strict_types=1);
namespace HybridTM\Tests\Console;

use HybridTM\Console\ExportCommand;
use HybridTM\Console\ImportCommand;
use HybridTM\Console\NormalizeCommand;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

final class ExportImportNormalizeCommandTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_ien_cmd_' . uniqid('', true);
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
    }

    private function removeDir(string $path): void
    {
        if (!is_dir($path)) return;
        foreach (scandir($path) as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            $full = $path . '/' . $entry;
            is_dir($full) ? $this->removeDir($full) : unlink($full);
        }
        rmdir($path);
    }

    private function writeDsl(string $filename, string $body): string
    {
        $path = $this->tmpDir . '/' . $filename;
        file_put_contents($path, "<?php\nuse HybridTM\\DSL\\ThreatModel;\nuse HybridTM\\DSL\\TechnicalAsset;\n{$body}\n");
        return $path;
    }

    // ── export ───────────────────────────────────────────────────────────────

    public function testExportFailsWhenDslMissing(): void
    {
        $tester = new CommandTester(new ExportCommand());
        $exit = $tester->execute(['--infra' => $this->tmpDir . '/nonexistent.php']);
        self::assertSame(1, $exit);
    }

    public function testExportWritesCanonicalJson(): void
    {
        $path = $this->writeDsl('model.php', <<<'PHP'
$model = new ThreatModel('My App');
$model->addTechnicalAsset(new TechnicalAsset('web'));
return $model;
PHP);
        $outPath = $this->tmpDir . '/out.json';

        $tester = new CommandTester(new ExportCommand());
        $exit = $tester->execute(['--infra' => $path, '--out' => $outPath, '--kb-version' => 'kb-core@1.0.0']);

        self::assertSame(0, $exit);
        $decoded = json_decode((string) file_get_contents($outPath), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('My App', $decoded['model']['title']);
        self::assertSame('kb-core@1.0.0', $decoded['kbVersion']);
        self::assertCount(1, $decoded['components']);
    }

    // ── import ───────────────────────────────────────────────────────────────

    public function testImportFailsWhenJsonMissing(): void
    {
        $tester = new CommandTester(new ImportCommand());
        $exit = $tester->execute(['--in' => $this->tmpDir . '/nonexistent.json']);
        self::assertSame(1, $exit);
    }

    public function testImportFailsOnInvalidJson(): void
    {
        $path = $this->tmpDir . '/bad.json';
        file_put_contents($path, 'not json {{{');

        $tester = new CommandTester(new ImportCommand());
        $exit = $tester->execute(['--in' => $path]);
        self::assertSame(1, $exit);
    }

    public function testImportGeneratesValidRequireablePhp(): void
    {
        $jsonPath = $this->tmpDir . '/model.json';
        file_put_contents($jsonPath, json_encode([
            'schemaVersion' => 1,
            'model' => ['title' => 'Imported App'],
            'components' => [['id' => 'web', 'name' => 'Web']],
        ], JSON_THROW_ON_ERROR));

        $outPath = $this->tmpDir . '/threat-model.php';
        $tester = new CommandTester(new ImportCommand());
        $exit = $tester->execute(['--in' => $jsonPath, '--out' => $outPath]);

        self::assertSame(0, $exit);
        self::assertStringContainsString('No syntax errors', (string) shell_exec('php -l ' . escapeshellarg($outPath) . ' 2>&1'));

        $model = require $outPath;
        self::assertSame('Imported App', $model->title);
        self::assertNotNull($model->getTechnicalAsset('web'));
    }

    // ── normalize ────────────────────────────────────────────────────────────

    public function testNormalizeFailsWhenDslMissing(): void
    {
        $tester = new CommandTester(new NormalizeCommand());
        $exit = $tester->execute(['--infra' => $this->tmpDir . '/nonexistent.php']);
        self::assertSame(1, $exit);
    }

    public function testNormalizeRewritesCanonicalFileToDeterministicForm(): void
    {
        $path = $this->writeDsl('model.php', <<<'PHP'
$model = new ThreatModel('App');
$web = new TechnicalAsset('web');
$model->addTechnicalAsset($web);
return $model;
PHP);
        $outPath = $this->tmpDir . '/normalized.php';

        $tester = new CommandTester(new NormalizeCommand());
        $exit = $tester->execute(['--infra' => $path, '--out' => $outPath]);

        self::assertSame(0, $exit);
        $model = require $outPath;
        self::assertSame('App', $model->title);
        self::assertNotNull($model->getTechnicalAsset('web'));
    }

    public function testNormalizeDefaultsToOverwritingInPlace(): void
    {
        $path = $this->writeDsl('model.php', <<<'PHP'
$model = new ThreatModel('App');
return $model;
PHP);
        $before = file_get_contents($path);

        $tester = new CommandTester(new NormalizeCommand());
        $exit = $tester->execute(['--infra' => $path]);

        self::assertSame(0, $exit);
        $after = file_get_contents($path);
        self::assertNotSame($before, $after, 'normalize should have rewritten the file in canonical form');

        $model = require $path;
        self::assertSame('App', $model->title);
    }

    public function testNormalizeRefusesNonCanonicalFileAndDoesNotModifyIt(): void
    {
        $path = $this->writeDsl('model.php', <<<'PHP'
$model = new ThreatModel('App');
foreach ([1, 2] as $x) {
    // non-canonical construct
}
return $model;
PHP);
        $before = file_get_contents($path);

        $tester = new CommandTester(new NormalizeCommand());
        $exit = $tester->execute(['--infra' => $path]);

        self::assertSame(1, $exit);
        self::assertStringContainsString('outside the recognizable subset', $tester->getDisplay());
        self::assertSame($before, file_get_contents($path), 'a non-canonical file must be left untouched');
    }

    public function testNormalizeIsIdempotent(): void
    {
        $path = $this->writeDsl('model.php', <<<'PHP'
$web = new TechnicalAsset('web', 'Web App');
$web->internet = true;
$model = new ThreatModel('App');
$model->addTechnicalAsset($web);
return $model;
PHP);

        (new CommandTester(new NormalizeCommand()))->execute(['--infra' => $path]);
        $firstPass = file_get_contents($path);

        (new CommandTester(new NormalizeCommand()))->execute(['--infra' => $path]);
        $secondPass = file_get_contents($path);

        self::assertSame($firstPass, $secondPass);
    }

    // ── export -> import round trip ─────────────────────────────────────────

    public function testExportThenImportRoundTrips(): void
    {
        $originalPath = $this->writeDsl('original.php', <<<'PHP'
$model = new ThreatModel('Round Trip App');
$web = new TechnicalAsset('web', 'Web');
$web->internet = true;
$model->addTechnicalAsset($web);
return $model;
PHP);

        $jsonPath = $this->tmpDir . '/model.json';
        (new CommandTester(new ExportCommand()))->execute(['--infra' => $originalPath, '--out' => $jsonPath]);

        $reimportedPath = $this->tmpDir . '/reimported.php';
        $exit = (new CommandTester(new ImportCommand()))->execute(['--in' => $jsonPath, '--out' => $reimportedPath]);

        self::assertSame(0, $exit);
        $model = require $reimportedPath;
        self::assertSame('Round Trip App', $model->title);
        self::assertTrue($model->getTechnicalAsset('web')->internet);
    }
}
