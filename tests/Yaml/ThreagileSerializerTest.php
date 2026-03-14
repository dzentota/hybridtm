<?php
declare(strict_types=1);
namespace HybridTM\Tests\Yaml;

use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Availability;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;
use HybridTM\Yaml\ThreagileSerializer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

final class ThreagileSerializerTest extends TestCase
{
    private ThreagileSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new ThreagileSerializer();
    }

    private function buildMinimalModel(string $title = 'Test Model'): ThreatModel
    {
        return new ThreatModel($title);
    }

    private function parse(ThreatModel $model): array
    {
        return Yaml::parse($this->serializer->serialize($model));
    }

    // ── Top-level fields ───────────────────────────────────────────────────────

    public function testTopLevelThreagileVersion(): void
    {
        $data = $this->parse($this->buildMinimalModel());
        self::assertSame('1.0.0', $data['threagile_version']);
    }

    public function testTopLevelTitle(): void
    {
        $data = $this->parse($this->buildMinimalModel('My Threat Model'));
        self::assertSame('My Threat Model', $data['title']);
    }

    public function testAuthorDefaultsToHybridTM(): void
    {
        $data = $this->parse($this->buildMinimalModel());
        self::assertSame('HybridTM', $data['author']['name']);
    }

    public function testAuthorCustomValue(): void
    {
        $model = $this->buildMinimalModel();
        $model->author = 'Alice';
        $data = $this->parse($model);
        self::assertSame('Alice', $data['author']['name']);
    }

    public function testDateDefaultsToCurrentYear(): void
    {
        $data = $this->parse($this->buildMinimalModel());
        self::assertMatchesRegularExpression('/^\d{4}-01-01$/', $data['date']);
    }

    public function testDateCustomValue(): void
    {
        $model = $this->buildMinimalModel();
        $model->date = '2025-06-15';
        $data = $this->parse($model);
        self::assertSame('2025-06-15', $data['date']);
    }

    public function testBusinessCriticalityEnum(): void
    {
        $model = $this->buildMinimalModel();
        $model->businessCriticality = BusinessCriticality::Critical;
        $data = $this->parse($model);
        self::assertSame('critical', $data['business_criticality']);
    }

    public function testTopLevelEmptyMapFields(): void
    {
        $data = $this->parse($this->buildMinimalModel());
        // These must be YAML maps, not sequences
        foreach (['questions', 'abuse_cases', 'security_requirements', 'shared_runtimes', 'individual_risk_categories', 'risk_tracking'] as $key) {
            self::assertIsArray($data[$key], "Field '$key' should be array (map)");
        }
    }

    // ── DataAssets ─────────────────────────────────────────────────────────────

    public function testDataAssetSerializedWithAllFields(): void
    {
        $model = $this->buildMinimalModel();
        $da = new DataAsset('user-email', 'User Email');
        $da->description = 'Email addresses of users';
        $da->usage = DataUsage::Business;
        $da->origin = DataOrigin::UserInput;
        $da->owner = 'marketing';
        $da->quantity = Quantity::Many;
        $da->confidentiality = Confidentiality::Restricted;
        $da->integrity = Integrity::Critical;
        $da->availability = Availability::Important;
        $da->justificationCiaRating = 'PII';
        $da->tags = ['pii'];
        $model->addDataAsset($da);

        $data = $this->parse($model);
        $asset = $data['data_assets']['user-email'];

        self::assertSame('user-email', $asset['id']);
        self::assertSame('Email addresses of users', $asset['description']);
        self::assertSame('business', $asset['usage']);
        self::assertSame('ui-input', $asset['origin']);
        self::assertSame('marketing', $asset['owner']);
        self::assertSame('many', $asset['quantity']);
        self::assertSame('restricted', $asset['confidentiality']);
        self::assertSame('critical', $asset['integrity']);
        self::assertSame('important', $asset['availability']);
        self::assertSame('PII', $asset['justification_cia_rating']);
        self::assertSame(['pii'], $asset['tags']);
    }

    public function testDataAssetsKeyedById(): void
    {
        $model = $this->buildMinimalModel();
        $model->addDataAsset(new DataAsset('asset-a'));
        $model->addDataAsset(new DataAsset('asset-b'));
        $data = $this->parse($model);
        self::assertArrayHasKey('asset-a', $data['data_assets']);
        self::assertArrayHasKey('asset-b', $data['data_assets']);
    }

    // ── TechnicalAssets ────────────────────────────────────────────────────────

    public function testTechnicalAssetSerializedWithAllFields(): void
    {
        $model = $this->buildMinimalModel();
        $ta = new TechnicalAsset('web-api', 'Web API');
        $ta->description = 'REST API';
        $ta->technology = Technology::WebServiceRest;
        $ta->machine = Machine::Container;
        $ta->encryption = Encryption::None;
        $ta->confidentiality = Confidentiality::Internal;
        $ta->integrity = Integrity::Operational;
        $ta->availability = Availability::Operational;
        $ta->owner = 'platform-team';
        $ta->customDevelopedParts = true;
        $ta->multiTenant = false;
        $ta->redundant = false;
        $ta->internet = true;
        $ta->dataAssetsProcessed = ['user-email'];
        $ta->dataAssetsStored = [];
        $ta->tags = ['web'];
        $model->addTechnicalAsset($ta);

        $data = $this->parse($model);
        $asset = $data['technical_assets']['web-api'];

        self::assertSame('web-api', $asset['id']);
        self::assertSame('REST API', $asset['description']);
        self::assertSame('web-service-rest', $asset['technology']);
        self::assertSame('container', $asset['machine']);
        self::assertSame('none', $asset['encryption']);
        self::assertSame('platform-team', $asset['owner']);
        self::assertTrue($asset['custom_developed_parts']);
        self::assertFalse($asset['multi_tenant']);
        self::assertTrue($asset['internet']);
        self::assertSame(['user-email'], $asset['data_assets_processed']);
        self::assertSame([], $asset['data_assets_stored']);
        self::assertSame(['web'], $asset['tags']);
    }

    public function testTechnicalAssetEmptyCommunicationLinksIsMap(): void
    {
        $model = $this->buildMinimalModel();
        $model->addTechnicalAsset(new TechnicalAsset('isolated'));

        $data = $this->parse($model);

        // Must be an associative array (map), not a sequential list
        $links = $data['technical_assets']['isolated']['communication_links'];
        self::assertIsArray($links);
        self::assertSame([], $links); // empty map
    }

    public function testEmptyCommunicationLinksNotSerializedAsSequenceInRawYaml(): void
    {
        $model = $this->buildMinimalModel();
        $model->addTechnicalAsset(new TechnicalAsset('svc'));

        $yaml = $this->serializer->serialize($model);

        // YAML list syntax [] must not appear for communication_links
        self::assertStringNotContainsString('communication_links: []', $yaml);
    }

    public function testTechnicalAssetCommunicationLinksSerializedCorrectly(): void
    {
        $model = $this->buildMinimalModel();
        $ta = new TechnicalAsset('web');
        $link = $ta->communicatesTo('db', Protocol::SqlAccessProtocol, Authentication::Credentials, Authorization::TechnicalUser);
        $link->vpn = true;
        $link->dataSent = ['payload'];
        $link->dataReceived = ['result'];
        $model->addTechnicalAsset($ta);

        $data = $this->parse($model);
        $links = $data['technical_assets']['web']['communication_links'];
        $link = $links['web-to-db'];

        self::assertSame('db', $link['target']);
        self::assertSame('sql-access-protocol', $link['protocol']);
        self::assertSame('credentials', $link['authentication']);
        self::assertSame('technical-user', $link['authorization']);
        self::assertTrue($link['vpn']);
        self::assertSame(['payload'], $link['data_assets_sent']);
        self::assertSame(['result'], $link['data_assets_received']);
    }

    public function testTechnicalAssetDeduplicatesDataAssetsProcessed(): void
    {
        $model = $this->buildMinimalModel();
        $ta = new TechnicalAsset('svc');
        $ta->dataAssetsProcessed = ['data-a', 'data-a', 'data-b'];
        $model->addTechnicalAsset($ta);

        $data = $this->parse($model);
        $processed = $data['technical_assets']['svc']['data_assets_processed'];
        self::assertCount(2, $processed);
    }

    // ── TrustBoundaries ────────────────────────────────────────────────────────

    public function testTrustBoundarySerializedCorrectly(): void
    {
        $model = $this->buildMinimalModel();
        $tb = new TrustBoundary('internal-net', 'Internal Network', TrustBoundaryType::NetworkOnPrem);
        $tb->description = 'On-premise network';
        $tb->addAssets('web-api', 'db');
        $tb->tags = ['internal'];
        $model->addTrustBoundary($tb);

        $data = $this->parse($model);
        $boundary = $data['trust_boundaries']['internal-net'];

        self::assertSame('internal-net', $boundary['id']);
        self::assertSame('On-premise network', $boundary['description']);
        self::assertSame('network-on-prem', $boundary['type']);
        self::assertContains('web-api', $boundary['technical_assets_inside']);
        self::assertContains('db', $boundary['technical_assets_inside']);
        self::assertSame(['internal'], $boundary['tags']);
    }

    public function testTrustBoundaryNestedBoundaries(): void
    {
        $model = $this->buildMinimalModel();
        $tb = new TrustBoundary('outer');
        $tb->trustBoundariesNested = ['inner'];
        $model->addTrustBoundary($tb);

        $data = $this->parse($model);
        self::assertContains('inner', $data['trust_boundaries']['outer']['trust_boundaries_nested']);
    }

    // ── YAML output format ─────────────────────────────────────────────────────

    public function testOutputIsValidYaml(): void
    {
        $model = $this->buildMinimalModel();
        $model->addTechnicalAsset(new TechnicalAsset('svc'));
        $yaml = $this->serializer->serialize($model);
        $parsed = Yaml::parse($yaml);
        self::assertIsArray($parsed);
    }

    public function testEmptyListsSerializeAsSequences(): void
    {
        $model = $this->buildMinimalModel();
        $ta = new TechnicalAsset('svc');
        $ta->dataAssetsProcessed = [];
        $model->addTechnicalAsset($ta);

        $data = $this->parse($model);
        self::assertIsArray($data['technical_assets']['svc']['data_assets_processed']);
        self::assertSame([], $data['technical_assets']['svc']['data_assets_processed']);
    }
}
