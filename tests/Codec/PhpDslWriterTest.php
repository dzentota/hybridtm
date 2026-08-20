<?php

declare(strict_types=1);

namespace HybridTM\Tests\Codec;

use HybridTM\Codec\PhpDslWriter;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;
use PHPUnit\Framework\TestCase;

final class PhpDslWriterTest extends TestCase
{
    private PhpDslWriter $writer;
    private string $tmpFile;

    protected function setUp(): void
    {
        $this->writer = new PhpDslWriter();
        $this->tmpFile = sys_get_temp_dir() . '/hybridtm_writer_' . uniqid('', true) . '.php';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tmpFile)) {
            unlink($this->tmpFile);
        }
    }

    /** Writes, lints, and require()s the generated file — a real executable round trip. */
    private function reload(ThreatModel $model): ThreatModel
    {
        $code = $this->writer->write($model);

        $lintResult = shell_exec('php -l ' . escapeshellarg($this->writeToTempFile($code)) . ' 2>&1');
        self::assertStringContainsString('No syntax errors', (string) $lintResult, "Generated code has a syntax error:\n{$code}");

        $reloaded = require $this->tmpFile;
        self::assertInstanceOf(ThreatModel::class, $reloaded);
        return $reloaded;
    }

    private function writeToTempFile(string $code): string
    {
        file_put_contents($this->tmpFile, $code);
        return $this->tmpFile;
    }

    public function testGeneratesValidPhpForMinimalModel(): void
    {
        $model = new ThreatModel('My App');
        $reloaded = $this->reload($model);

        self::assertSame('My App', $reloaded->title);
    }

    public function testRoundTripsModelMeta(): void
    {
        $model = new ThreatModel('My App');
        $model->description = "It's a test";
        $model->author = 'Alice';
        $model->date = '2026-01-01';
        $model->businessCriticality = BusinessCriticality::Critical;
        $model->managementSummaryComment = 'summary';

        $reloaded = $this->reload($model);

        self::assertSame('My App', $reloaded->title);
        self::assertSame("It's a test", $reloaded->description);
        self::assertSame('Alice', $reloaded->author);
        self::assertSame('2026-01-01', $reloaded->date);
        self::assertSame(BusinessCriticality::Critical, $reloaded->businessCriticality);
        self::assertSame('summary', $reloaded->managementSummaryComment);
    }

    public function testRoundTripsDataAsset(): void
    {
        $model = new ThreatModel('App');
        $da = new DataAsset('customer-pii', "O'Brien's Data");
        $da->description = 'PII';
        $da->confidentiality = Confidentiality::Confidential;
        $da->tags = ['pii', 'gdpr'];
        $model->addDataAsset($da);

        $reloaded = $this->reload($model)->getDataAsset('customer-pii');

        self::assertNotNull($reloaded, "'customer-pii' must round-trip");
        self::assertSame("O'Brien's Data", $reloaded->name);
        self::assertSame('PII', $reloaded->description);
        self::assertSame(Confidentiality::Confidential, $reloaded->confidentiality);
        self::assertSame(['pii', 'gdpr'], $reloaded->tags);
    }

    public function testRoundTripsTechnicalAssetCoreFields(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('web-api', 'Web API');
        $asset->technology = Technology::WebServiceRest;
        $asset->encryption = Encryption::Transparent;
        $asset->internet = true;
        $asset->traits = ['datastore', 'sql_engine'];
        $model->addTechnicalAsset($asset);

        $reloaded = $this->reload($model)->getTechnicalAsset('web-api');

        self::assertNotNull($reloaded, "'web-api' must round-trip");
        self::assertSame('Web API', $reloaded->name);
        self::assertSame(Technology::WebServiceRest, $reloaded->technology);
        self::assertSame(Encryption::Transparent, $reloaded->encryption);
        self::assertTrue($reloaded->internet);
        self::assertSame(['datastore', 'sql_engine'], $reloaded->traits);
    }

    public function testRoundTripsSimpleCommunicationLink(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db', Protocol::SqlAccessProtocolEncrypted, Authentication::Credentials, Authorization::TechnicalUser, 'query');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $reloaded = $this->reload($model)->getTechnicalAsset('web');
        self::assertNotNull($reloaded, "'web' must round-trip");
        $link = $reloaded->communicationLinks['web-to-db'];

        self::assertSame('db', $link->targetAssetId);
        self::assertSame(Protocol::SqlAccessProtocolEncrypted, $link->protocol);
        self::assertSame(Authentication::Credentials, $link->authentication);
        self::assertSame(Authorization::TechnicalUser, $link->authorization);
        self::assertSame('query', $link->description);
    }

    public function testRoundTripsCommunicationLinkNeedingCapturedAssignment(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db');
        $link->vpn = true;
        $link->dataSent = ['payload'];
        $link->dataReceived = ['result'];
        $link->tags = ['internal'];
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $reloaded = $this->reload($model)->getTechnicalAsset('web');
        self::assertNotNull($reloaded, "'web' must round-trip");
        $decodedLink = $reloaded->communicationLinks['web-to-db'];

        self::assertTrue($decodedLink->vpn);
        self::assertSame(['payload'], $decodedLink->dataSent);
        self::assertSame(['result'], $decodedLink->dataReceived);
        self::assertSame(['internal'], $decodedLink->tags);
    }

    public function testRoundTripsTrustBoundary(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $model->addTrustBoundary(new TrustBoundary('outer'));
        $tb = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
        $tb->description = 'edge zone';
        $tb->addAssets('web');
        $tb->trustBoundariesNested = ['outer'];
        $tb->tags = ['pci'];
        $model->addTrustBoundary($tb);

        $reloaded = $this->reload($model)->getTrustBoundaries()['dmz'];

        self::assertSame('DMZ', $reloaded->name);
        self::assertSame('edge zone', $reloaded->description);
        self::assertSame(TrustBoundaryType::NetworkCloudSecurityGroup, $reloaded->type);
        self::assertSame(['web'], $reloaded->technicalAssetsInside);
        self::assertSame(['outer'], $reloaded->trustBoundariesNested);
        self::assertSame(['pci'], $reloaded->tags);
    }

    public function testWriteIsDeterministicAcrossCalls(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('d'));
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        self::assertSame($this->writer->write($model), $this->writer->write($model));
    }

    public function testVariableNameCollisionIsResolvedDeterministically(): void
    {
        // A data asset and a technical asset sharing the same id would
        // otherwise both want the variable name $shared.
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('shared'));
        $model->addTechnicalAsset(new TechnicalAsset('shared'));

        $reloaded = $this->reload($model);
        self::assertNotNull($reloaded->getDataAsset('shared'));
        self::assertNotNull($reloaded->getTechnicalAsset('shared'));
    }

    public function testWriteRoundTripsExampleThreatModel(): void
    {
        $model = require __DIR__ . '/../../example/threat-model.php';
        self::assertInstanceOf(ThreatModel::class, $model);

        $reloaded = $this->reload($model);

        self::assertSame($model->title, $reloaded->title);
        self::assertSame(count($model->getTechnicalAssets()), count($reloaded->getTechnicalAssets()));
        self::assertSame(count($model->getDataAssets()), count($reloaded->getDataAssets()));
        self::assertSame(count($model->getTrustBoundaries()), count($reloaded->getTrustBoundaries()));

        foreach ($model->getTechnicalAssets() as $id => $asset) {
            $decoded = $reloaded->getTechnicalAsset($id);
            self::assertNotNull($decoded, "asset '{$id}' must survive the round trip");
            self::assertCount(count($asset->communicationLinks), $decoded->communicationLinks);
        }
    }
}
