<?php
declare(strict_types=1);
namespace HybridTM\Tests\Console;

use HybridTM\Console\InitCommand;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Availability;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\Integrity;
use PHPUnit\Framework\TestCase;

/**
 * InitCommand's interactive wizard is not driven end-to-end here (that
 * needs a full QuestionHelper input simulation); instead this exercises
 * buildModel()/generatePhp() directly via reflection, the way the wizard's
 * own execute() calls them after collecting answers (T-4.2: InitCommand
 * now delegates code generation to PhpDslWriter instead of building the
 * string itself).
 */
final class InitCommandGeneratePhpTest extends TestCase
{
    private string $tmpFile;

    protected function setUp(): void
    {
        $this->tmpFile = sys_get_temp_dir() . '/hybridtm_init_' . uniqid('', true) . '.php';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tmpFile)) {
            unlink($this->tmpFile);
        }
    }

    private function command(): InitCommand
    {
        return new InitCommand();
    }

    private function set(InitCommand $command, string $property, mixed $value): void
    {
        $ref = new \ReflectionProperty(InitCommand::class, $property);
        $ref->setValue($command, $value);
    }

    private function call(InitCommand $command, string $method): mixed
    {
        $ref = new \ReflectionMethod(InitCommand::class, $method);
        return $ref->invoke($command);
    }

    public function testBuildModelMapsWizardAnswersOntoThreatModel(): void
    {
        $command = $this->command();
        $this->set($command, 'modelTitle', 'My App');
        $this->set($command, 'modelDescription', 'A test app');
        $this->set($command, 'modelAuthor', 'Security Team');
        $this->set($command, 'modelCriticality', 'critical');
        $this->set($command, 'dataAssets', [[
            'id' => 'customer-pii', 'name' => 'Customer PII', 'desc' => 'PII data',
            'confidentiality' => 'confidential', 'integrity' => 'important', 'availability' => 'important',
            'origin' => 'ui-input', 'quantity' => 'many',
        ]]);
        $this->set($command, 'technicalAssets', [[
            'id' => 'web', 'name' => 'Web App', 'desc' => '',
            'type' => 'process', 'technology' => 'web-service-rest', 'machine' => 'container', 'size' => 'service',
            'internet' => true, 'encryption' => 'none',
            'confidentiality' => 'internal', 'integrity' => 'operational', 'availability' => 'operational',
            'processedData' => ['customer-pii'], 'storedData' => [],
        ]]);

        $model = $this->call($command, 'buildModel');

        self::assertInstanceOf(ThreatModel::class, $model);
        self::assertSame('My App', $model->title);
        self::assertSame(BusinessCriticality::Critical, $model->businessCriticality);
        self::assertSame(Confidentiality::Confidential, $model->getDataAsset('customer-pii')->confidentiality);
        self::assertSame(Integrity::Important, $model->getDataAsset('customer-pii')->integrity);
        self::assertSame(Availability::Important, $model->getDataAsset('customer-pii')->availability);
        self::assertTrue($model->getTechnicalAsset('web')->internet);
        self::assertSame(['customer-pii'], $model->getTechnicalAsset('web')->dataAssetsProcessed);
    }

    public function testGeneratePhpProducesValidRequireableCode(): void
    {
        $command = $this->command();
        $this->set($command, 'modelTitle', 'My App');
        $this->set($command, 'modelDescription', 'A test app');
        $this->set($command, 'modelAuthor', 'Security Team');
        $this->set($command, 'modelCriticality', 'important');
        $this->set($command, 'dataAssets', []);
        $this->set($command, 'technicalAssets', []);
        $this->set($command, 'trustBoundaries', []);
        $this->set($command, 'communicationLinks', []);

        $code = $this->call($command, 'generatePhp');

        self::assertStringStartsWith("<?php\ndeclare(strict_types=1);\n", $code);
        self::assertStringContainsString('HybridTM — My App', $code);
        self::assertStringContainsString('A test app', $code);

        file_put_contents($this->tmpFile, $code);
        self::assertStringContainsString('No syntax errors', (string) shell_exec('php -l ' . escapeshellarg($this->tmpFile) . ' 2>&1'));

        $model = require $this->tmpFile;
        self::assertInstanceOf(ThreatModel::class, $model);
        self::assertSame('My App', $model->title);
    }

    public function testGeneratePhpStampsCurrentDate(): void
    {
        $command = $this->command();
        $this->set($command, 'modelTitle', 'App');
        $this->set($command, 'modelDescription', '');
        $this->set($command, 'modelAuthor', '');
        $this->set($command, 'modelCriticality', 'important');
        $this->set($command, 'dataAssets', []);
        $this->set($command, 'technicalAssets', []);
        $this->set($command, 'trustBoundaries', []);
        $this->set($command, 'communicationLinks', []);

        $code = $this->call($command, 'generatePhp');
        file_put_contents($this->tmpFile, $code);
        $model = require $this->tmpFile;

        self::assertSame(date('Y-m-d'), $model->date);
    }
}
