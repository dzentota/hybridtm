<?php
declare(strict_types=1);
namespace HybridTM\Tests\Compiler;

use HybridTM\Compiler\AstScanner;
use HybridTM\Compiler\DataFlowVisitor;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;

final class AstScannerTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/hybridtm_test_' . uniqid('', true);
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

    private function write(string $filename, string $code): string
    {
        $path = $this->tmpDir . '/' . $filename;
        file_put_contents($path, $code);
        return $path;
    }

    private function parse(string $code): \HybridTM\Compiler\AstResult
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $visitor = new DataFlowVisitor();
        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);
        $stmts = $parser->parse($code);
        $traverser->traverse($stmts ?? []);
        return $visitor->getResult();
    }

    // ── DataFlowVisitor unit tests ─────────────────────────────────────────────

    public function testVisitorExtractsDataFlow(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;
use HybridTM\Enums\Protocol;

class MyService {
    #[DataFlow(target: 'db', protocol: Protocol::SqlAccessProtocol)]
    public function save(): void {}
}
PHP);
        self::assertCount(1, $result->dataFlows);
        $flow = $result->dataFlows[0];
        self::assertSame('db', $flow->targetAssetId);
        self::assertSame(Protocol::SqlAccessProtocol, $flow->protocol);
    }

    public function testVisitorExtractsAssetId(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;

#[AssetId('my-service')]
class MyService {
    #[DataFlow(target: 'db')]
    public function save(): void {}
}
PHP);
        self::assertCount(1, $result->dataFlows);
        self::assertSame('my-service', $result->dataFlows[0]->sourceAssetId);
    }

    public function testVisitorResetsAssetIdBetweenClasses(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;

#[AssetId('svc-a')]
class ServiceA {
    #[DataFlow(target: 'db')]
    public function queryA(): void {}
}

class ServiceB {
    #[DataFlow(target: 'cache')]
    public function queryB(): void {}
}
PHP);
        self::assertCount(2, $result->dataFlows);
        self::assertSame('svc-a', $result->dataFlows[0]->sourceAssetId);
        self::assertSame('', $result->dataFlows[1]->sourceAssetId);
    }

    public function testVisitorExtractsMitigation(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\Mitigation;
use HybridTM\Enums\MitigationStatus;

class MyService {
    #[Mitigation(cwe: 'CWE-89', description: 'Use PDO', status: MitigationStatus::Mitigated)]
    public function query(): void {}
}
PHP);
        self::assertCount(1, $result->mitigations);
        $m = $result->mitigations[0];
        self::assertSame('CWE-89', $m->cwe);
        self::assertSame('Use PDO', $m->description);
        self::assertSame(MitigationStatus::Mitigated, $m->status);
    }

    public function testVisitorExtractsProcessesDataOnClass(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\ProcessesData;

#[ProcessesData(dataAssets: ['user-pii', 'session'])]
class MyService {}
PHP);
        self::assertCount(1, $result->processesData);
        self::assertSame(['user-pii', 'session'], $result->processesData[0]->dataAssets);
    }

    public function testVisitorExtractsProcessesDataOnMethod(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\ProcessesData;

class MyService {
    #[ProcessesData(dataAssets: ['token'])]
    public function authenticate(): void {}
}
PHP);
        self::assertCount(1, $result->processesData);
        self::assertSame(['token'], $result->processesData[0]->dataAssets);
    }

    public function testVisitorWarnsOnMissingDataFlowTarget(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;

class MyService {
    #[DataFlow()]
    public function brokenMethod(): void {}
}
PHP);
        self::assertCount(0, $result->dataFlows);
        self::assertNotEmpty($result->warnings);
        self::assertStringContainsString('Missing required', $result->warnings[0]);
    }

    public function testVisitorExtractsDataFlowBooleanArgs(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;

class MyService {
    #[DataFlow(target: 'svc', vpn: true, ipFiltered: true, readonly: false)]
    public function send(): void {}
}
PHP);
        $flow = $result->dataFlows[0];
        self::assertTrue($flow->vpn);
        self::assertTrue($flow->ipFiltered);
        self::assertFalse($flow->readonly);
    }

    public function testVisitorExtractsDataSentAndReceived(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;

class MyService {
    #[DataFlow(target: 'db', dataSent: ['payload'], dataReceived: ['result'])]
    public function call(): void {}
}
PHP);
        $flow = $result->dataFlows[0];
        self::assertSame(['payload'], $flow->dataSent);
        self::assertSame(['result'], $flow->dataReceived);
    }

    public function testVisitorExtractsMultipleDataFlowsOnMethod(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;

class MyService {
    #[DataFlow(target: 'svc-a')]
    #[DataFlow(target: 'svc-b')]
    public function fanOut(): void {}
}
PHP);
        self::assertCount(2, $result->dataFlows);
        $targets = array_map(fn($f) => $f->targetAssetId, $result->dataFlows);
        self::assertContains('svc-a', $targets);
        self::assertContains('svc-b', $targets);
    }

    public function testVisitorContextIncludesClassAndMethod(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;

class OrderController {
    #[DataFlow(target: 'payment-svc')]
    public function checkout(): void {}
}
PHP);
        self::assertStringContainsString('OrderController', $result->dataFlows[0]->context);
        self::assertStringContainsString('checkout', $result->dataFlows[0]->context);
    }

    public function testVisitorExtractsAuthenticationEnum(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;
use HybridTM\Enums\Authentication;

class MyService {
    #[DataFlow(target: 'db', authentication: Authentication::Credentials)]
    public function connect(): void {}
}
PHP);
        self::assertSame(Authentication::Credentials, $result->dataFlows[0]->authentication);
    }

    public function testVisitorHandlesMitigationDefaultStatus(): void
    {
        $result = $this->parse(<<<'PHP'
<?php
use HybridTM\Attributes\Mitigation;

class MyService {
    #[Mitigation(cwe: 'CWE-79', description: 'Escape output')]
    public function render(): void {}
}
PHP);
        self::assertSame(MitigationStatus::Mitigated, $result->mitigations[0]->status);
    }

    // ── AstScanner integration tests ───────────────────────────────────────────

    public function testScannerFindsDataFlowsInDirectory(): void
    {
        $this->write('Controller.php', <<<'PHP'
<?php
use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;

#[AssetId('web')]
class Controller {
    #[DataFlow(target: 'db')]
    public function index(): void {}
}
PHP);
        $scanner = new AstScanner();
        $result = $scanner->scan($this->tmpDir);

        self::assertCount(1, $result->dataFlows);
        self::assertSame('web', $result->dataFlows[0]->sourceAssetId);
        self::assertSame('db', $result->dataFlows[0]->targetAssetId);
    }

    public function testScannerScansSubdirectories(): void
    {
        mkdir($this->tmpDir . '/Services', 0755, true);
        $this->write('Services/UserService.php', <<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;

class UserService {
    #[DataFlow(target: 'users-db')]
    public function find(): void {}
}
PHP);
        $scanner = new AstScanner();
        $result = $scanner->scan($this->tmpDir);

        self::assertCount(1, $result->dataFlows);
        self::assertSame('users-db', $result->dataFlows[0]->targetAssetId);
    }

    public function testScannerSkipsNonPhpFiles(): void
    {
        $this->write('notes.txt', '#[DataFlow(target: "db")]');
        $scanner = new AstScanner();
        $result = $scanner->scan($this->tmpDir);
        self::assertCount(0, $result->dataFlows);
    }

    public function testScannerRecordsParseWarningOnInvalidPhp(): void
    {
        // A file with an unterminated string is guaranteed to be a parse error
        $this->write('broken.php', '<?php $x = "unterminated string');
        $scanner = new AstScanner();
        $result = $scanner->scan($this->tmpDir);
        self::assertNotEmpty($result->warnings);
    }

    public function testScannerAggregatesMultipleFiles(): void
    {
        $this->write('A.php', <<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;
class A { #[DataFlow(target: 'x')] public function go(): void {} }
PHP);
        $this->write('B.php', <<<'PHP'
<?php
use HybridTM\Attributes\DataFlow;
class B { #[DataFlow(target: 'y')] public function go(): void {} }
PHP);
        $scanner = new AstScanner();
        $result = $scanner->scan($this->tmpDir);

        self::assertCount(2, $result->dataFlows);
    }

    public function testScannerEmptyDirectoryReturnsEmptyResult(): void
    {
        $scanner = new AstScanner();
        $result = $scanner->scan($this->tmpDir);

        self::assertSame([], $result->dataFlows);
        self::assertSame([], $result->mitigations);
        self::assertSame([], $result->processesData);
        self::assertSame([], $result->warnings);
    }
}
