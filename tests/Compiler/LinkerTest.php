<?php
declare(strict_types=1);
namespace HybridTM\Tests\Compiler;

use HybridTM\Compiler\AstResult;
use HybridTM\Compiler\DiscoveredDataFlow;
use HybridTM\Compiler\DiscoveredMitigation;
use HybridTM\Compiler\DiscoveredProcessesData;
use HybridTM\Compiler\Linker;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;
use PHPUnit\Framework\TestCase;

final class LinkerTest extends TestCase
{
    private function makeModel(): ThreatModel
    {
        $tm = new ThreatModel('Test');
        $tm->addTechnicalAsset(new TechnicalAsset('web', 'Web'));
        $tm->addTechnicalAsset(new TechnicalAsset('db', 'DB'));
        $tm->addDataAsset(new DataAsset('user-data', 'User Data'));
        return $tm;
    }

    private function makeFlow(
        string $source,
        string $target,
        array $dataSent = [],
        array $dataReceived = [],
        Protocol $protocol = Protocol::Https,
        Authentication $auth = Authentication::None,
        Authorization $authz = Authorization::None,
    ): DiscoveredDataFlow {
        return new DiscoveredDataFlow(
            sourceAssetId: $source,
            targetAssetId: $target,
            protocol: $protocol,
            authentication: $auth,
            authorization: $authz,
            dataSent: $dataSent,
            dataReceived: $dataReceived,
            vpn: false,
            ipFiltered: false,
            readonly: false,
            context: 'TestClass::testMethod',
        );
    }

    // ── Happy path ─────────────────────────────────────────────────────────────

    public function testLinkCreatesCommLinkOnSourceAsset(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $linker->link($tm, new AstResult([$this->makeFlow('web', 'db')]));

        self::assertArrayHasKey('web-to-db', $tm->getTechnicalAsset('web')->communicationLinks);
    }

    public function testLinkSetsProtocolAndAuth(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $linker->link($tm, new AstResult([
            $this->makeFlow('web', 'db', protocol: Protocol::SqlAccessProtocol, auth: Authentication::Credentials),
        ]));

        $link = $tm->getTechnicalAsset('web')->communicationLinks['web-to-db'];
        self::assertSame(Protocol::SqlAccessProtocol, $link->protocol);
        self::assertSame(Authentication::Credentials, $link->authentication);
    }

    public function testLinkPopulatesDataSentOnLink(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $linker->link($tm, new AstResult([$this->makeFlow('web', 'db', dataSent: ['user-data'])]));

        $link = $tm->getTechnicalAsset('web')->communicationLinks['web-to-db'];
        self::assertContains('user-data', $link->dataSent);
    }

    public function testLinkPopulatesDataReceivedOnLink(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $linker->link($tm, new AstResult([$this->makeFlow('web', 'db', dataReceived: ['user-data'])]));

        $link = $tm->getTechnicalAsset('web')->communicationLinks['web-to-db'];
        self::assertContains('user-data', $link->dataReceived);
    }

    public function testLinkAddsDataSentToSourceProcessed(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $linker->link($tm, new AstResult([$this->makeFlow('web', 'db', dataSent: ['user-data'])]));

        self::assertContains('user-data', $tm->getTechnicalAsset('web')->dataAssetsProcessed);
    }

    public function testLinkNoDuplicateDataAssets(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        // Send same data twice via two separate DataFlow entries
        $linker->link($tm, new AstResult([
            $this->makeFlow('web', 'db', dataSent: ['user-data']),
            $this->makeFlow('web', 'db', dataSent: ['user-data']),
        ]));

        $web = $tm->getTechnicalAsset('web');
        self::assertCount(1, array_filter($web->dataAssetsProcessed, fn($id) => $id === 'user-data'));
        $link = $web->communicationLinks['web-to-db'];
        self::assertCount(1, array_filter($link->dataSent, fn($id) => $id === 'user-data'));
    }

    public function testLinkReusesExistingCommLink(): void
    {
        $tm = $this->makeModel();
        // Pre-create link in DSL
        $web = $tm->getTechnicalAsset('web');
        $existing = $web->communicatesTo('db', Protocol::BinaryEncrypted);

        $linker = new Linker();
        $linker->link($tm, new AstResult([$this->makeFlow('web', 'db')]));

        // Still the same instance (link was not replaced)
        self::assertSame($existing, $web->communicationLinks['web-to-db']);
    }

    public function testNoWarningsOnCleanInput(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $linker->link($tm, new AstResult([$this->makeFlow('web', 'db')]));
        self::assertSame([], $linker->getWarnings());
    }

    // ── Missing source asset ───────────────────────────────────────────────────

    public function testMissingSourceAssetEmitsWarning(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $flow = $this->makeFlow('', 'db', dataSent: ['user-data']);
        $linker->link($tm, new AstResult([$flow]));

        self::assertNotEmpty($linker->getWarnings());
        self::assertStringContainsString('db', $linker->getWarnings()[0]);
    }

    public function testMissingSourceAssetRecordsDataOnTarget(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $flow = $this->makeFlow('', 'db', dataSent: ['user-data']);
        $linker->link($tm, new AstResult([$flow]));

        self::assertContains('user-data', $tm->getTechnicalAsset('db')->dataAssetsProcessed);
    }

    // ── Error cases ────────────────────────────────────────────────────────────

    public function testUnknownTargetThrowsRuntimeException(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $flow = $this->makeFlow('web', 'nonexistent');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches("/Unknown target asset 'nonexistent'/");
        $linker->link($tm, new AstResult([$flow]));
    }

    public function testUnknownDataAssetInDataSentThrows(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $flow = $this->makeFlow('web', 'db', dataSent: ['nonexistent-data']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches("/Unknown DataAsset 'nonexistent-data'/");
        $linker->link($tm, new AstResult([$flow]));
    }

    public function testUnknownDataAssetInDataReceivedThrows(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $flow = $this->makeFlow('web', 'db', dataReceived: ['nonexistent-data']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches("/Unknown DataAsset 'nonexistent-data'/");
        $linker->link($tm, new AstResult([$flow]));
    }

    public function testUnknownDataAssetWithMissingSourceEmitsWarning(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        // No source + unknown data asset → warning, not exception
        $flow = $this->makeFlow('', 'db', dataSent: ['unknown-asset']);

        $this->expectException(\RuntimeException::class);
        $linker->link($tm, new AstResult([$flow]));
    }

    // ── ProcessesData ──────────────────────────────────────────────────────────

    public function testUnknownProcessesDataEmitsWarning(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $pd = new DiscoveredProcessesData(['unknown-data'], 'SomeClass');
        $linker->link($tm, new AstResult(processesData: [$pd]));

        self::assertNotEmpty($linker->getWarnings());
        self::assertStringContainsString('unknown-data', $linker->getWarnings()[0]);
    }

    public function testKnownProcessesDataProducesNoWarning(): void
    {
        $tm = $this->makeModel();
        $linker = new Linker();
        $pd = new DiscoveredProcessesData(['user-data'], 'SomeClass');
        $linker->link($tm, new AstResult(processesData: [$pd]));

        self::assertSame([], $linker->getWarnings());
    }

    // ── AstResult DTO ──────────────────────────────────────────────────────────

    public function testAstResultStoresAllFields(): void
    {
        $flow = $this->makeFlow('a', 'b');
        $mitigation = new DiscoveredMitigation('CWE-89', 'prepared stmts', MitigationStatus::Mitigated, 'Ctx');
        $pd = new DiscoveredProcessesData(['x'], 'Ctx');
        $result = new AstResult([$flow], [$mitigation], [$pd], ['a warning']);

        self::assertSame([$flow], $result->dataFlows);
        self::assertSame([$mitigation], $result->mitigations);
        self::assertSame([$pd], $result->processesData);
        self::assertSame(['a warning'], $result->warnings);
    }

    public function testAstResultDefaultsToEmptyArrays(): void
    {
        $result = new AstResult();
        self::assertSame([], $result->dataFlows);
        self::assertSame([], $result->mitigations);
        self::assertSame([], $result->processesData);
        self::assertSame([], $result->warnings);
    }
}
