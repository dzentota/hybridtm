<?php
declare(strict_types=1);
namespace HybridTM\Tests\Console;

use HybridTM\Console\AnalyzeCommand;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

final class AnalyzeCommandTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        // RuleEngine's constructor always builds a RuleExpressionProvider,
        // even for the no-KB/no-rules test cases below.
        if (!class_exists(ExpressionLanguage::class)) {
            self::markTestSkipped('symfony/expression-language is not installed.');
        }

        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_analyze_cmd_' . uniqid('', true);
        mkdir($this->tmpDir, 0755, true);
        mkdir($this->tmpDir . '/kb', 0755, true);
    }

    protected function tearDown(): void
    {
        if (isset($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
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

    private function writeDsl(string $body): string
    {
        $path = $this->tmpDir . '/threat-model.php';
        file_put_contents($path, "<?php\nuse HybridTM\\DSL\\ThreatModel;\nuse HybridTM\\DSL\\TechnicalAsset;\n{$body}\n");
        return $path;
    }

    private function writeKbFiles(): void
    {
        file_put_contents($this->tmpDir . '/kb/threat.yaml', <<<YAML
apiVersion: hybridtm.io/kb/v1
kind: Threat
metadata: { id: THREAT-DATA-AT-REST-UNENCRYPTED, version: 1.0.0 }
spec:
  title: Unencrypted data at rest
  summary: summary
  stride: [information-disclosure]
  base: { likelihood: likely, impact: medium }
YAML);
        file_put_contents($this->tmpDir . '/kb/rule.yaml', <<<YAML
apiVersion: hybridtm.io/kb/v1
kind: Rule
metadata: { id: storage/unencrypted-at-rest, priority: 100 }
spec:
  scope: component
  when:
    all: ["component.hasTrait('datastore')", "component.encryption == 'none'"]
  then:
    - raise: THREAT-DATA-AT-REST-UNENCRYPTED
YAML);
    }

    private function tester(): CommandTester
    {
        return new CommandTester(new AnalyzeCommand());
    }

    public function testFailsWhenDslFileMissing(): void
    {
        $tester = $this->tester();
        $exit = $tester->execute(['--infra' => $this->tmpDir . '/nonexistent.php']);

        self::assertSame(1, $exit);
        self::assertStringContainsString('not found', $tester->getDisplay());
    }

    public function testFailsWhenDslDoesNotReturnThreatModel(): void
    {
        $path = $this->writeDsl('return "not a model";');
        $tester = $this->tester();
        $exit = $tester->execute(['--infra' => $path]);

        self::assertSame(1, $exit);
        self::assertStringContainsString('ThreatModel instance', $tester->getDisplay());
    }

    public function testFailsOnInvalidMinSeverity(): void
    {
        $path = $this->writeDsl("return new ThreatModel('App');");
        $exit = $this->tester()->execute(['--infra' => $path, '--min-severity' => 'nonsense']);
        self::assertSame(1, $exit);
    }

    public function testFailsOnInvalidFailOn(): void
    {
        $path = $this->writeDsl("return new ThreatModel('App');");
        $exit = $this->tester()->execute(['--infra' => $path, '--fail-on' => 'nonsense']);
        self::assertSame(1, $exit);
    }

    public function testFailsOnUnsupportedFormat(): void
    {
        $path = $this->writeDsl("return new ThreatModel('App');");
        $exit = $this->tester()->execute(['--infra' => $path, '--format' => 'sarif']);
        self::assertSame(1, $exit);
    }

    public function testFailsOnModelValidationError(): void
    {
        $path = $this->writeDsl(<<<'PHP'
$model = new ThreatModel('App');
$web = new TechnicalAsset('web');
$web->communicatesTo('nonexistent');
$model->addTechnicalAsset($web);
return $model;
PHP);
        $tester = $this->tester();
        $exit = $tester->execute(['--infra' => $path]);

        self::assertSame(1, $exit);
        self::assertStringContainsString('validation failed', $tester->getDisplay());
    }

    public function testSucceedsWithNoFindingsAndEmptyKb(): void
    {
        $path = $this->writeDsl("return new ThreatModel('App');");
        $tester = $this->tester();
        $exit = $tester->execute(['--infra' => $path]);

        self::assertSame(0, $exit);
        self::assertStringContainsString('No findings', $tester->getDisplay());
    }

    public function testJsonFormatOutputsValidJson(): void
    {
        $path = $this->writeDsl("return new ThreatModel('App');");
        $tester = $this->tester();
        $tester->execute(['--infra' => $path, '--format' => 'json']);

        $decoded = json_decode($tester->getDisplay(), true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('findings', $decoded);
    }

    public function testFindsIssueWithRealKb(): void
    {
        $this->writeKbFiles();
        $path = $this->writeDsl(<<<'PHP'
$model = new ThreatModel('App');
$db = new TechnicalAsset('db');
$db->traits = ['datastore'];
$model->addTechnicalAsset($db);
return $model;
PHP);

        $tester = $this->tester();
        $exit = $tester->execute(['--infra' => $path, '--kb' => [$this->tmpDir . '/kb'], '--format' => 'json']);

        self::assertSame(0, $exit, 'no --fail-on given, so a finding does not fail the command');
        $decoded = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        self::assertCount(1, $decoded['findings']);
        self::assertSame('THREAT-DATA-AT-REST-UNENCRYPTED', $decoded['findings'][0]['threatId']);
    }

    public function testFailOnGatesExitCode(): void
    {
        $this->writeKbFiles();
        $path = $this->writeDsl(<<<'PHP'
$model = new ThreatModel('App');
$db = new TechnicalAsset('db');
$db->traits = ['datastore'];
$model->addTechnicalAsset($db);
return $model;
PHP);

        $tester = $this->tester();
        // storage/unencrypted-at-rest -> likely x medium -> Elevated severity.
        $exit = $tester->execute(['--infra' => $path, '--kb' => [$this->tmpDir . '/kb'], '--fail-on' => 'elevated']);

        self::assertSame(1, $exit);
    }

    public function testFailOnDoesNotTriggerBelowThreshold(): void
    {
        $this->writeKbFiles();
        $path = $this->writeDsl(<<<'PHP'
$model = new ThreatModel('App');
$db = new TechnicalAsset('db');
$db->traits = ['datastore'];
$model->addTechnicalAsset($db);
return $model;
PHP);

        $tester = $this->tester();
        $exit = $tester->execute(['--infra' => $path, '--kb' => [$this->tmpDir . '/kb'], '--fail-on' => 'critical']);

        self::assertSame(0, $exit);
    }
}
