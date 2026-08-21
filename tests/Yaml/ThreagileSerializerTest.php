<?php

declare(strict_types=1);

namespace HybridTM\Tests\Yaml;

use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\IndividualRiskCategory;
use HybridTM\DSL\Question;
use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\SecurityRequirement;
use HybridTM\DSL\SharedRuntime;
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
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\RiskFunction;
use HybridTM\Enums\Stride;
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

    /** @return array<string, mixed> */
    private function parse(ThreatModel $model): array
    {
        $parsed = Yaml::parse($this->serializer->serialize($model));
        self::assertIsArray($parsed);
        return $parsed;
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

    // ── Governance sections (T-1.1) ─────────────────────────────────────────────

    public function testQuestionsSerialized(): void
    {
        $model = $this->buildMinimalModel();
        $model->addQuestion(new Question('pentest-done', 'Was a pentest performed?', 'Not yet planned'));

        $data = $this->parse($model);
        self::assertSame('Not yet planned', $data['questions']['pentest-done']);
    }

    public function testQuestionWithoutAnswerSerializesEmptyString(): void
    {
        $model = $this->buildMinimalModel();
        $model->addQuestion(new Question('open-q', 'Unanswered?'));

        $data = $this->parse($model);
        self::assertSame('', $data['questions']['open-q']);
    }

    public function testAbuseCasesSerialized(): void
    {
        $model = $this->buildMinimalModel();
        $model->addAbuseCase(new AbuseCase('steal-data', 'Attacker exfiltrates customer PII'));

        $data = $this->parse($model);
        self::assertSame('Attacker exfiltrates customer PII', $data['abuse_cases']['steal-data']);
    }

    public function testSecurityRequirementsSerialized(): void
    {
        $model = $this->buildMinimalModel();
        $model->addSecurityRequirement(new SecurityRequirement('firewall', 'Corporate firewall in place'));

        $data = $this->parse($model);
        self::assertSame('Corporate firewall in place', $data['security_requirements']['firewall']);
    }

    public function testSharedRuntimeSerialized(): void
    {
        $model = $this->buildMinimalModel();
        $runtime = new SharedRuntime('k8s-node-1', 'Kubernetes Node 1');
        $runtime->description = 'Shared worker node';
        $runtime->tags = ['prod'];
        $runtime->addAssets('web', 'worker');
        $model->addSharedRuntime($runtime);

        $data = $this->parse($model);
        $serialized = $data['shared_runtimes']['k8s-node-1'];

        self::assertSame('k8s-node-1', $serialized['id']);
        self::assertSame('Shared worker node', $serialized['description']);
        self::assertSame(['prod'], $serialized['tags']);
        self::assertSame(['web', 'worker'], $serialized['technical_assets_running']);
    }

    public function testIndividualRiskCategorySerialized(): void
    {
        $model = $this->buildMinimalModel();
        $category = new IndividualRiskCategory('custom-prompt-injection');
        $category->title = 'Prompt Injection';
        $category->description = 'LLM input is not isolated from instructions';
        $category->function = RiskFunction::Development;
        $category->stride = [Stride::Tampering, Stride::ElevationOfPrivilege];
        $category->cwe = ['CWE-1427'];
        $model->addIndividualRiskCategory($category);

        $data = $this->parse($model);
        $serialized = $data['individual_risk_categories']['custom-prompt-injection'];

        self::assertSame('Prompt Injection', $serialized['title']);
        self::assertSame('development', $serialized['function']);
        self::assertSame(['tampering', 'elevation-of-privilege'], $serialized['stride']);
        self::assertSame(['CWE-1427'], $serialized['cwe']);
    }

    public function testRiskTrackingSerialized(): void
    {
        $model = $this->buildMinimalModel();
        $tracking = new RiskTracking('unencrypted-storage@user-db');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'Compensating control in place';
        $tracking->ticket = 'JIRA-123';
        $tracking->date = '2026-01-01';
        $tracking->checkedBy = 'Alice';
        $model->addRiskTracking($tracking);

        $data = $this->parse($model);
        $serialized = $data['risk_tracking']['unencrypted-storage@user-db'];

        self::assertSame('accepted', $serialized['status']);
        self::assertSame('Compensating control in place', $serialized['justification']);
        self::assertSame('JIRA-123', $serialized['ticket']);
        self::assertSame('Alice', $serialized['checked_by']);
    }

    // ── TechnologyList (ADR-10, T-1.4) ──────────────────────────────────────────

    public function testSingleTechnologyStillUsesLegacyScalarField(): void
    {
        $model = $this->buildMinimalModel();
        $ta = new TechnicalAsset('web');
        $ta->technology = Technology::ReverseProxy;
        $model->addTechnicalAsset($ta);

        $data = $this->parse($model);
        $asset = $data['technical_assets']['web'];

        self::assertSame('reverse-proxy', $asset['technology']);
        self::assertArrayNotHasKey('technologies', $asset);
    }

    public function testMultipleTechnologiesUseListField(): void
    {
        $model = $this->buildMinimalModel();
        $ta = new TechnicalAsset('nginx');
        $ta->technologies->add(Technology::ReverseProxy)->add(Technology::WebServer)->add('load-balancer');
        $model->addTechnicalAsset($ta);

        $data = $this->parse($model);
        $asset = $data['technical_assets']['nginx'];

        self::assertSame(['reverse-proxy', 'web-server', 'load-balancer'], $asset['technologies']);
        self::assertArrayNotHasKey('technology', $asset);
    }

    public function testUnusedTechnologiesFieldProducesByteIdenticalYaml(): void
    {
        // Backward compatibility (T-1.4 DoD): a model that never touches
        // $technologies must serialize exactly as before this feature existed.
        $before = $this->buildMinimalModel();
        $before->addTechnicalAsset(new TechnicalAsset('svc'));

        $after = $this->buildMinimalModel();
        $ta = new TechnicalAsset('svc');
        self::assertSame(0, $ta->technologies->count());
        $after->addTechnicalAsset($ta);

        self::assertSame($this->serializer->serialize($before), $this->serializer->serialize($after));
    }

    public function testGovernanceSectionsStillEmptyMapsWhenUnused(): void
    {
        $data = $this->parse($this->buildMinimalModel());

        foreach (['shared_runtimes', 'individual_risk_categories', 'risk_tracking', 'questions', 'abuse_cases', 'security_requirements'] as $key) {
            self::assertSame([], $data[$key], "Field '$key' should remain an empty map when unused");
        }
    }
}
