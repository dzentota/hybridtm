<?php
declare(strict_types=1);
namespace HybridTM\Tests\Codec;

use HybridTM\Codec\PhpDslReader;
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

final class PhpDslReaderTest extends TestCase
{
    private PhpDslReader $reader;

    protected function setUp(): void
    {
        $this->reader = new PhpDslReader();
    }

    // ── basic recognition ───────────────────────────────────────────────────

    public function testReadsMinimalModel(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('My App');
return $model;
PHP);

        self::assertTrue($result->isCanonical());
        self::assertInstanceOf(ThreatModel::class, $result->model);
        self::assertSame('My App', $result->model->title);
    }

    public function testReadsModelMetaPropertyAssignments(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\BusinessCriticality;
$model = new ThreatModel('App');
$model->description = 'desc';
$model->author = 'Alice';
$model->date = '2026-01-01';
$model->businessCriticality = BusinessCriticality::Critical;
return $model;
PHP);

        self::assertTrue($result->isCanonical());
        self::assertSame('desc', $result->model->description);
        self::assertSame('Alice', $result->model->author);
        self::assertSame('2026-01-01', $result->model->date);
        self::assertSame(BusinessCriticality::Critical, $result->model->businessCriticality);
    }

    public function testReadsDataAssetWithEnumsAndArray(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Confidentiality;
$model = new ThreatModel('App');
$pii = new DataAsset('customer-pii', 'Customer PII');
$pii->confidentiality = Confidentiality::Confidential;
$pii->tags = ['pii', 'gdpr'];
$model->addDataAsset($pii);
return $model;
PHP);

        self::assertTrue($result->isCanonical());
        $asset = $result->model->getDataAsset('customer-pii');
        self::assertSame('Customer PII', $asset->name);
        self::assertSame(Confidentiality::Confidential, $asset->confidentiality);
        self::assertSame(['pii', 'gdpr'], $asset->tags);
    }

    public function testReadsTechnicalAssetAndCommunicatesTo(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Technology;
$model = new ThreatModel('App');
$web = new TechnicalAsset('web', 'Web App');
$web->technology = Technology::WebServiceRest;
$web->internet = true;
$web->traits = ['datastore'];
$web->communicatesTo(
    targetId: 'db',
    protocol: Protocol::SqlAccessProtocolEncrypted,
    authentication: Authentication::Credentials,
    authorization: Authorization::TechnicalUser,
    description: 'query',
);
$model->addTechnicalAsset($web);
$db = new TechnicalAsset('db');
$model->addTechnicalAsset($db);
return $model;
PHP);

        self::assertTrue($result->isCanonical());
        $web = $result->model->getTechnicalAsset('web');
        self::assertSame(Technology::WebServiceRest, $web->technology);
        self::assertTrue($web->internet);
        self::assertSame(['datastore'], $web->traits);

        $link = $web->communicationLinks['web-to-db'];
        self::assertSame('db', $link->targetAssetId);
        self::assertSame(Protocol::SqlAccessProtocolEncrypted, $link->protocol);
        self::assertSame(Authentication::Credentials, $link->authentication);
        self::assertSame(Authorization::TechnicalUser, $link->authorization);
        self::assertSame('query', $link->description);
    }

    public function testReadsCapturedCommunicationLinkAssignment(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
$web = new TechnicalAsset('web');
$webToDbLink = $web->communicatesTo(targetId: 'db');
$webToDbLink->vpn = true;
$webToDbLink->dataSent = ['payload'];
$model->addTechnicalAsset($web);
$model->addTechnicalAsset(new TechnicalAsset('db'));
return $model;
PHP);

        // `new TechnicalAsset('db')` as a bare inline arg (not assigned to a
        // variable first) is outside the subset — addTechnicalAsset's
        // argument must be a tracked variable. This exercises that this
        // failure doesn't stop the rest of the file from being read.
        self::assertFalse($result->isCanonical());
        $link = $result->model->getTechnicalAsset('web')->communicationLinks['web-to-db'];
        self::assertTrue($link->vpn);
        self::assertSame(['payload'], $link->dataSent);
    }

    public function testReadsTrustBoundaryWithAddAssets(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\TrustBoundaryType;
$model = new ThreatModel('App');
$web = new TechnicalAsset('web');
$model->addTechnicalAsset($web);
$dmz = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
$dmz->description = 'edge';
$dmz->addAssets('web');
$model->addTrustBoundary($dmz);
return $model;
PHP);

        self::assertTrue($result->isCanonical());
        $boundary = $result->model->getTrustBoundaries()['dmz'];
        self::assertSame('DMZ', $boundary->name);
        self::assertSame('edge', $boundary->description);
        self::assertSame(TrustBoundaryType::NetworkCloudSecurityGroup, $boundary->type);
        self::assertSame(['web'], $boundary->technicalAssetsInside);
    }

    // ── non-canonical detection ──────────────────────────────────────────────

    public function testFlagsForeachLoopAsNonCanonical(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
foreach ([1, 2, 3] as $x) {
    echo $x;
}
return $model;
PHP);

        self::assertFalse($result->isCanonical());
        self::assertNotEmpty($result->nonCanonical);
    }

    public function testFlagsFunctionCallAsNonCanonical(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\DataAsset;
$model = new ThreatModel('App');
$pii = new DataAsset('pii');
$pii->description = strtoupper('hello');
$model->addDataAsset($pii);
return $model;
PHP);

        self::assertFalse($result->isCanonical());
        self::assertStringContainsString('literal', (string) $result->nonCanonical[0]);
    }

    public function testFlagsStringConcatenationAsNonCanonical(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\DataAsset;
$model = new ThreatModel('App');
$prefix = 'pii-';
$pii = new DataAsset('pii');
$pii->description = $prefix . 'data';
$model->addDataAsset($pii);
return $model;
PHP);

        self::assertFalse($result->isCanonical());
    }

    public function testNonCanonicalConstructIncludesLineNumber(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
if (true) {
}
return $model;
PHP);

        self::assertFalse($result->isCanonical());
        self::assertSame(4, $result->nonCanonical[0]->line);
    }

    public function testParseErrorIsReportedAsNonCanonical(): void
    {
        $result = $this->reader->read('<?php $x = "unterminated');

        self::assertFalse($result->isCanonical());
        self::assertNull($result->model);
    }

    public function testUnknownPropertyAssignmentIsNonCanonical(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\DataAsset;
$model = new ThreatModel('App');
$pii = new DataAsset('pii');
$pii->thisPropertyDoesNotExist = 'x';
$model->addDataAsset($pii);
return $model;
PHP);

        // PHP allows setting an undeclared dynamic property to be permissive
        // in some configurations, but HybridTM's DSL classes are not
        // #[AllowDynamicProperties] — this should fail and be recorded.
        self::assertFalse($result->isCanonical());
    }

    // ── round trip through PhpDslWriter ──────────────────────────────────────

    public function testRoundTripsWriterOutputForRichModel(): void
    {
        $model = new ThreatModel('My App');
        $model->description = "It's rich";
        $model->businessCriticality = BusinessCriticality::Critical;

        $model->addDataAsset(new DataAsset('pii', 'PII'));

        $web = new TechnicalAsset('web', 'Web');
        $web->technology = Technology::WebServiceRest;
        $web->encryption = Encryption::Transparent;
        $web->traits = ['datastore'];
        $web->communicatesTo('db', Protocol::SqlAccessProtocolEncrypted, Authentication::Credentials, Authorization::TechnicalUser);
        $model->addTechnicalAsset($web);
        $model->addTechnicalAsset(new TechnicalAsset('db'));

        $boundary = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
        $boundary->addAssets('web');
        $model->addTrustBoundary($boundary);

        $code = (new PhpDslWriter())->write($model);
        $result = $this->reader->read($code);

        self::assertTrue($result->isCanonical(), 'PhpDslWriter output must always be canonical: ' . implode('; ', array_map('strval', $result->nonCanonical)));
        self::assertSame('My App', $result->model->title);
        self::assertSame("It's rich", $result->model->description);
        self::assertSame(BusinessCriticality::Critical, $result->model->businessCriticality);
        self::assertEquals($model->getDataAsset('pii'), $result->model->getDataAsset('pii'));
        self::assertSame(Technology::WebServiceRest, $result->model->getTechnicalAsset('web')->technology);
        self::assertSame(['datastore'], $result->model->getTechnicalAsset('web')->traits);
        self::assertCount(1, $result->model->getTechnicalAsset('web')->communicationLinks);
        self::assertSame(['web'], $result->model->getTrustBoundaries()['dmz']->technicalAssetsInside);
    }

    public function testRoundTripsExampleThreatModelSource(): void
    {
        $code = file_get_contents(__DIR__ . '/../../example/threat-model.php');
        self::assertIsString($code);

        $result = $this->reader->read($code);

        self::assertTrue($result->isCanonical(), 'example/threat-model.php should be fully canonical: ' . implode('; ', array_map('strval', $result->nonCanonical)));

        $expected = require __DIR__ . '/../../example/threat-model.php';
        self::assertSame($expected->title, $result->model->title);
        self::assertSame(count($expected->getTechnicalAssets()), count($result->model->getTechnicalAssets()));
        self::assertSame(count($expected->getDataAssets()), count($result->model->getDataAssets()));
        self::assertSame(count($expected->getTrustBoundaries()), count($result->model->getTrustBoundaries()));

        foreach ($expected->getTechnicalAssets() as $id => $asset) {
            $decoded = $result->model->getTechnicalAsset($id);
            self::assertNotNull($decoded, "asset '{$id}' must be recognized");
            self::assertSame($asset->name, $decoded->name);
            self::assertCount(count($asset->communicationLinks), $decoded->communicationLinks);
        }
    }

    public function testWriteReadWriteIsIdempotent(): void
    {
        $model = require __DIR__ . '/../../example/threat-model.php';
        $writer = new PhpDslWriter();

        $firstWrite = $writer->write($model);
        $reRead = $this->reader->read($firstWrite);
        self::assertTrue($reRead->isCanonical());

        $secondWrite = $writer->write($reRead->model);

        self::assertSame($firstWrite, $secondWrite, 'write(read(write(m))) must equal write(m) byte-for-byte (T-4.4)');
    }
}
