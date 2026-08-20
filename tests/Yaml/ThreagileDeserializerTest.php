<?php

declare(strict_types=1);

namespace HybridTM\Tests\Yaml;

use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\IndividualRiskCategory;
use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\SecurityRequirement;
use HybridTM\DSL\SharedRuntime;
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
use HybridTM\Yaml\ThreagileDeserializer;
use HybridTM\Yaml\ThreagileSerializer;
use PHPUnit\Framework\TestCase;

final class ThreagileDeserializerTest extends TestCase
{
    private ThreagileSerializer $serializer;
    private ThreagileDeserializer $deserializer;

    protected function setUp(): void
    {
        $this->serializer = new ThreagileSerializer();
        $this->deserializer = new ThreagileDeserializer();
    }

    private function roundTrip(ThreatModel $model): ThreatModel
    {
        return $this->deserializer->deserialize($this->serializer->serialize($model));
    }

    // ── field-level reads ────────────────────────────────────────────────────

    public function testReadsTopLevelFields(): void
    {
        $model = new ThreatModel('My App');
        $model->author = 'Alice';
        $model->date = '2025-06-15';
        $model->businessCriticality = BusinessCriticality::Critical;
        $model->managementSummaryComment = 'summary';

        $roundTripped = $this->roundTrip($model);

        self::assertSame('My App', $roundTripped->title);
        self::assertSame('Alice', $roundTripped->author);
        self::assertSame('2025-06-15', $roundTripped->date);
        self::assertSame(BusinessCriticality::Critical, $roundTripped->businessCriticality);
        self::assertSame('summary', $roundTripped->managementSummaryComment);
    }

    public function testModelDescriptionHasNoYamlRepresentation(): void
    {
        // Threagile's own schema has no top-level `description` field, only
        // `management_summary_comment` — see class docblock.
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $model->author = 'Someone';
        $model->description = 'This is lost.';

        self::assertSame('', $this->roundTrip($model)->description);
    }

    public function testReadsDataAsset(): void
    {
        // $name has no Threagile YAML representation (like PropertyBag and
        // traits) and so cannot survive a round trip — use id === name here
        // and assert that limitation explicitly elsewhere.
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $da = new DataAsset('user-email');
        $da->description = 'Email addresses';
        $da->origin = DataOrigin::UserInput;
        $da->owner = 'marketing';
        $da->quantity = Quantity::Many;
        $da->confidentiality = Confidentiality::Restricted;
        $da->integrity = Integrity::Critical;
        $da->availability = Availability::Important;
        $da->justificationCiaRating = 'PII';
        $da->tags = ['pii'];
        $model->addDataAsset($da);

        $roundTripped = $this->roundTrip($model)->getDataAsset('user-email');

        self::assertEquals($da, $roundTripped);
    }

    public function testReadsTechnicalAssetWithCommunicationLink(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $web = new TechnicalAsset('web-api'); // see note on $name in testReadsDataAsset
        $web->description = 'REST API';
        $web->type = AssetType::Process;
        $web->technology = Technology::WebServiceRest;
        $web->machine = Machine::Container;
        $web->encryption = Encryption::None;
        $web->owner = 'platform-team';
        $web->customDevelopedParts = true;
        $web->internet = true;
        $web->dataAssetsProcessed = ['user-email'];
        $web->tags = ['web'];
        $link = $web->communicatesTo('db', Protocol::SqlAccessProtocol, Authentication::Credentials, Authorization::TechnicalUser);
        $link->vpn = true;
        $link->dataSent = ['payload'];
        $link->dataReceived = ['result'];
        $model->addDataAsset(new DataAsset('user-email'));
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $roundTripped = $this->roundTrip($model);

        self::assertEquals($web, $roundTripped->getTechnicalAsset('web-api'));
    }

    public function testReadsMultipleTechnologiesList(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $nginx = new TechnicalAsset('nginx');
        $nginx->technologies->add(Technology::ReverseProxy)->add(Technology::WebServer)->add('load-balancer');
        $model->addTechnicalAsset($nginx);

        $roundTripped = $this->roundTrip($model)->getTechnicalAsset('nginx');
        self::assertNotNull($roundTripped, 'Expected the nginx technical asset to round-trip.');

        self::assertSame(
            ['reverse-proxy', 'web-server', 'load-balancer'],
            $roundTripped->technologies->values(),
        );
    }

    public function testReadsTrustBoundary(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $model->addTechnicalAsset(new TechnicalAsset('web-api'));
        $model->addTechnicalAsset(new TechnicalAsset('db'));
        $tb = new TrustBoundary('internal-net', type: TrustBoundaryType::NetworkOnPrem); // see note on $name above
        $tb->description = 'On-premise network';
        $tb->addAssets('web-api', 'db');
        $tb->tags = ['internal'];
        $model->addTrustBoundary($tb);

        $roundTripped = $this->roundTrip($model)->getTrustBoundaries()['internal-net'];

        self::assertEquals($tb, $roundTripped);
    }

    public function testReadsNestedTrustBoundaries(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $outer = new TrustBoundary('outer');
        $outer->trustBoundariesNested = ['inner'];
        $inner = new TrustBoundary('inner');
        $model->addTrustBoundary($outer)->addTrustBoundary($inner);

        $roundTripped = $this->roundTrip($model);

        self::assertSame(['inner'], $roundTripped->getTrustBoundaries()['outer']->trustBoundariesNested);
    }

    public function testReadsAbuseCasesAndSecurityRequirements(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $model->addAbuseCase(new AbuseCase('steal-data', 'Attacker exfiltrates PII'));
        $model->addSecurityRequirement(new SecurityRequirement('firewall', 'Corporate firewall in place'));

        $roundTripped = $this->roundTrip($model);

        self::assertEquals(new AbuseCase('steal-data', 'Attacker exfiltrates PII'), $roundTripped->getAbuseCases()['steal-data']);
        self::assertEquals(
            new SecurityRequirement('firewall', 'Corporate firewall in place'),
            $roundTripped->getSecurityRequirements()['firewall'],
        );
    }

    public function testReadsSharedRuntime(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $runtime = new SharedRuntime('k8s-node-1', 'k8s-node-1');
        $runtime->description = 'Shared worker node';
        $runtime->tags = ['prod'];
        $runtime->addAssets('web', 'worker');
        $model->addSharedRuntime($runtime);

        $roundTripped = $this->roundTrip($model)->getSharedRuntimes()['k8s-node-1'];

        self::assertEquals($runtime, $roundTripped);
    }

    public function testReadsIndividualRiskCategory(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $category = new IndividualRiskCategory('custom-prompt-injection');
        $category->title = 'Prompt Injection';
        $category->description = 'LLM input is not isolated from instructions';
        $category->function = RiskFunction::Development;
        $category->stride = [Stride::Tampering, Stride::ElevationOfPrivilege];
        $category->cwe = ['CWE-1427'];
        $model->addIndividualRiskCategory($category);

        $roundTripped = $this->roundTrip($model)->getIndividualRiskCategories()['custom-prompt-injection'];

        self::assertEquals($category, $roundTripped);
    }

    public function testReadsRiskTracking(): void
    {
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $tracking = new RiskTracking('unencrypted-storage@user-db');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'Compensating control in place';
        $tracking->ticket = 'JIRA-123';
        $tracking->date = '2026-01-01';
        $tracking->checkedBy = 'Alice';
        $model->addRiskTracking($tracking);

        $roundTripped = $this->roundTrip($model)->getRiskTracking()['unencrypted-storage@user-db'];

        self::assertEquals($tracking, $roundTripped);
    }

    public function testDisplayNameHasNoYamlRepresentationAndDoesNotSurviveRoundTrip(): void
    {
        // Documents a known, deliberate limitation (see class docblock):
        // ThreagileSerializer never emits $name, only $id, so it cannot come
        // back — the same category of loss as PropertyBag and traits.
        $model = new ThreatModel('App');
        $model->date = '2025-01-01';
        $model->addTechnicalAsset(new TechnicalAsset('web-api', 'Web API'));

        $roundTripped = $this->roundTrip($model)->getTechnicalAsset('web-api');
        self::assertNotNull($roundTripped, 'Expected the web-api technical asset to round-trip.');

        self::assertSame('web-api', $roundTripped->name, 'name degrades to id, it is not preserved');
    }

    // ── whole-model round trips ──────────────────────────────────────────────

    public function testRoundTripsMinimalModel(): void
    {
        $model = new ThreatModel('Minimal');
        $model->date = '2025-01-01';
        $model->author = 'Nobody'; // an empty author would come back as the serializer's 'HybridTM' default

        self::assertEquals($model, $this->roundTrip($model));
    }

    public function testRoundTripsModelWithMultipleAssetsAndLinks(): void
    {
        $model = new ThreatModel('Multi-Asset App');
        $model->date = '2025-01-01';
        $model->author = 'Bob';
        $model->businessCriticality = BusinessCriticality::Important;

        $model->addDataAsset(new DataAsset('customer-pii'));
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->dataAssetsProcessed = ['customer-pii'];
        $web->communicatesTo('db', Protocol::SqlAccessProtocol);
        $db = new TechnicalAsset('db');
        $db->dataAssetsStored = ['customer-pii'];
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        $dmz = new TrustBoundary('dmz', type: TrustBoundaryType::NetworkCloudSecurityGroup);
        $dmz->addAssets('web');
        $model->addTrustBoundary($dmz);

        self::assertEquals($model, $this->roundTrip($model));
    }

    public function testRoundTripsExampleThreatModel(): void
    {
        $model = require __DIR__ . '/../../example/threat-model.php';
        self::assertInstanceOf(ThreatModel::class, $model);

        // The example builds `date` implicitly via the serializer default;
        // pin it so both sides of the round trip agree (see class docblock).
        $model->date = '2025-01-01';

        // The example gives its entities human display names distinct from
        // their id ("Web Application (Symfony BFF)" for "web-app"), which —
        // like PropertyBag and traits — has no Threagile YAML representation
        // and cannot come back (see testDisplayNameHasNoYamlRepresentation...).
        // Normalize both sides to id === name before comparing everything else.
        $this->normalizeDisplayNames($model);
        $roundTripped = $this->roundTrip($model);
        $this->normalizeDisplayNames($roundTripped);

        // $description likewise has no YAML representation (see class docblock).
        $model->description = '';

        self::assertEquals($model, $roundTripped);
    }

    private function normalizeDisplayNames(ThreatModel $model): void
    {
        foreach ($model->getDataAssets() as $asset) {
            $asset->name = $asset->id;
        }
        foreach ($model->getTechnicalAssets() as $asset) {
            $asset->name = $asset->id;
        }
        foreach ($model->getTrustBoundaries() as $boundary) {
            $boundary->name = $boundary->id;
        }
        foreach ($model->getSharedRuntimes() as $runtime) {
            $runtime->name = $runtime->id;
        }
    }
}
