<?php

declare(strict_types=1);

namespace HybridTM\Tests\Codec;

use HybridTM\Codec\ModelJsonCodec;
use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\DataAsset;
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
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;
use PHPUnit\Framework\TestCase;

final class ModelJsonCodecTest extends TestCase
{
    private ModelJsonCodec $codec;

    protected function setUp(): void
    {
        $this->codec = new ModelJsonCodec();
    }

    private function roundTrip(ThreatModel $model): ThreatModel
    {
        $encoded = $this->codec->encode($model);
        $reEncoded = json_decode((string) json_encode($encoded, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        return $this->codec->decode($reEncoded);
    }

    // ── top level ────────────────────────────────────────────────────────────

    public function testEncodesSchemaVersion(): void
    {
        $encoded = $this->codec->encode(new ThreatModel('App'));
        self::assertSame(1, $encoded['schemaVersion']);
    }

    public function testRoundTripsModelMeta(): void
    {
        $model = new ThreatModel('My App');
        $model->description = 'desc';
        $model->author = 'Alice';
        $model->date = '2026-01-01';
        $model->businessCriticality = BusinessCriticality::Critical;
        $model->managementSummaryComment = 'summary';

        $result = $this->roundTrip($model);

        self::assertSame('My App', $result->title);
        self::assertSame('desc', $result->description);
        self::assertSame('Alice', $result->author);
        self::assertSame('2026-01-01', $result->date);
        self::assertSame(BusinessCriticality::Critical, $result->businessCriticality);
        self::assertSame('summary', $result->managementSummaryComment);
    }

    public function testMinimalModelRoundTrips(): void
    {
        $model = new ThreatModel('Minimal');
        $result = $this->roundTrip($model);

        self::assertSame('Minimal', $result->title);
        self::assertSame([], $result->getTechnicalAssets());
        self::assertSame([], $result->getDataAssets());
    }

    // ── data assets ──────────────────────────────────────────────────────────

    public function testRoundTripsDataAssetAllFields(): void
    {
        $model = new ThreatModel('App');
        $da = new DataAsset('customer-pii', 'Customer PII');
        $da->description = 'PII data';
        $da->origin = DataOrigin::UserInput;
        $da->owner = 'Marketing';
        $da->quantity = Quantity::VeryMany;
        $da->confidentiality = Confidentiality::Confidential;
        $da->integrity = Integrity::Important;
        $da->availability = Availability::Important;
        $da->justificationCiaRating = 'GDPR';
        $da->tags = ['pii', 'gdpr'];
        $model->addDataAsset($da);

        $result = $this->roundTrip($model)->getDataAsset('customer-pii');

        self::assertEquals($da, $result);
    }

    // ── components ───────────────────────────────────────────────────────────

    public function testRoundTripsComponentCoreFields(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('web-api', 'Web API');
        $asset->description = 'REST API';
        $asset->technology = Technology::WebServiceRest;
        $asset->machine = Machine::Container;
        $asset->encryption = Encryption::Transparent;
        $asset->internet = true;
        $asset->redundant = true;
        $asset->customDevelopedParts = true;
        $asset->traits = ['datastore', 'sql_engine'];
        $asset->properties->set('foo', 'bar');
        $asset->dataAssetsProcessed = ['pii'];
        $asset->dataAssetsStored = ['pii'];
        $asset->dataFormatsAccepted = ['json'];
        $asset->tags = ['web'];
        $model->addDataAsset(new DataAsset('pii'));
        $model->addTechnicalAsset($asset);

        $result = $this->roundTrip($model)->getTechnicalAsset('web-api');

        self::assertNotNull($result, 'round-tripped model must still have the web-api component');
        self::assertSame('Web API', $result->name);
        self::assertSame('REST API', $result->description);
        self::assertSame(Technology::WebServiceRest, $result->technology);
        self::assertSame(Machine::Container, $result->machine);
        self::assertSame(Encryption::Transparent, $result->encryption);
        self::assertTrue($result->internet);
        self::assertTrue($result->redundant);
        self::assertTrue($result->customDevelopedParts);
        self::assertSame(['datastore', 'sql_engine'], $result->traits);
        self::assertSame('bar', $result->properties->get('foo'));
        self::assertSame(['pii'], $result->dataAssetsProcessed);
        self::assertSame(['pii'], $result->dataAssetsStored);
        self::assertSame(['json'], $result->dataFormatsAccepted);
        self::assertSame(['web'], $result->tags);
    }

    public function testRoundTripsKbComponentMarker(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('nginx');
        $asset->tags = ['kb-component:web-server-nginx@1.4.0', 'edge'];
        $model->addTechnicalAsset($asset);

        $encoded = $this->codec->encode($model);
        $component = $encoded['components'][0];

        self::assertSame('web-server-nginx', $component['kbComponent']);
        self::assertSame('1.4.0', $component['kbVersion']);
        self::assertSame(['edge'], $component['tags'], 'marker tag is not duplicated into the plain tags list');

        $result = $this->roundTrip($model)->getTechnicalAsset('nginx');
        self::assertNotNull($result, 'round-tripped model must still have the nginx component');
        self::assertContains('kb-component:web-server-nginx@1.4.0', $result->tags);
        self::assertContains('edge', $result->tags);
    }

    public function testRoundTripsMultiValueTechnologies(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('nginx');
        $asset->technologies->add(Technology::ReverseProxy)->add(Technology::WebServer)->add('load-balancer');
        $model->addTechnicalAsset($asset);

        $result = $this->roundTrip($model)->getTechnicalAsset('nginx');
        self::assertNotNull($result, 'round-tripped model must still have the nginx component');
        self::assertSame(['reverse-proxy', 'web-server', 'load-balancer'], $result->technologies->values());
    }

    public function testDefaultBooleanFieldsAreOmittedFromOverrides(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('svc'));

        $encoded = $this->codec->encode($model);
        $overrides = $encoded['components'][0]['overrides'];

        foreach (['internet', 'multiTenant', 'redundant', 'customDevelopedParts', 'usedAsClientByHuman', 'outOfScope'] as $key) {
            self::assertArrayNotHasKey($key, $overrides, "default-false '{$key}' should not appear in overrides");
        }
    }

    // ── trust boundaries ─────────────────────────────────────────────────────

    public function testRoundTripsTrustBoundary(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $model->addTrustBoundary(new TrustBoundary('outer', 'Outer', TrustBoundaryType::NetworkCloudProvider));
        $tb = new TrustBoundary('dmz', 'DMZ', TrustBoundaryType::NetworkCloudSecurityGroup);
        $tb->description = 'edge';
        $tb->addAssets('web');
        $tb->trustBoundariesNested = ['outer'];
        $tb->tags = ['pci'];
        $model->addTrustBoundary($tb);

        $result = $this->roundTrip($model)->getTrustBoundaries()['dmz'];

        self::assertSame('DMZ', $result->name);
        self::assertSame('edge', $result->description);
        self::assertSame(TrustBoundaryType::NetworkCloudSecurityGroup, $result->type);
        self::assertSame(['web'], $result->technicalAssetsInside);
        self::assertSame(['outer'], $result->trustBoundariesNested);
        self::assertSame(['pci'], $result->tags);
    }

    // ── data flows / communication links ────────────────────────────────────

    public function testRoundTripsCommunicationLink(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db', Protocol::SqlAccessProtocolEncrypted, Authentication::Credentials, Authorization::TechnicalUser, 'query db');
        $link->vpn = true;
        $link->ipFiltered = true;
        $link->dataSent = ['payload'];
        $link->dataReceived = ['result'];
        $link->properties->set('mtls', true);
        $link->tags = ['internal'];
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $result = $this->roundTrip($model);
        $webAsset = $result->getTechnicalAsset('web');
        self::assertNotNull($webAsset, 'round-tripped model must still have the web component');
        $decodedLink = $webAsset->communicationLinks['web-to-db'];

        self::assertSame('db', $decodedLink->targetAssetId);
        self::assertSame('query db', $decodedLink->description);
        self::assertSame(Protocol::SqlAccessProtocolEncrypted, $decodedLink->protocol);
        self::assertSame(Authentication::Credentials, $decodedLink->authentication);
        self::assertSame(Authorization::TechnicalUser, $decodedLink->authorization);
        self::assertTrue($decodedLink->vpn);
        self::assertTrue($decodedLink->ipFiltered);
        self::assertSame(['payload'], $decodedLink->dataSent);
        self::assertSame(['result'], $decodedLink->dataReceived);
        self::assertTrue($decodedLink->properties->get('mtls'));
        self::assertSame(['internal'], $decodedLink->tags);
    }

    public function testMultipleLinksFromSameSourceRoundTrip(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db');
        $web->communicatesTo('cache');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'))->addTechnicalAsset(new TechnicalAsset('cache'));

        $result = $this->roundTrip($model)->getTechnicalAsset('web');
        self::assertNotNull($result, 'round-tripped model must still have the web component');
        self::assertCount(2, $result->communicationLinks);
    }

    // ── shared runtimes / risk tracking / questions / abuse cases ───────────

    public function testRoundTripsSharedRuntime(): void
    {
        $model = new ThreatModel('App');
        $runtime = new SharedRuntime('node-1', 'Node 1');
        $runtime->description = 'shared host';
        $runtime->addAssets('web', 'worker');
        $runtime->tags = ['prod'];
        $model->addSharedRuntime($runtime);

        $result = $this->roundTrip($model)->getSharedRuntimes()['node-1'];
        self::assertEquals($runtime, $result);
    }

    public function testRoundTripsRiskTracking(): void
    {
        $model = new ThreatModel('App');
        $tracking = new RiskTracking('abc123');
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'Compensating control in place, reviewed quarterly.';
        $tracking->ticket = 'JIRA-1';
        $tracking->expiresAt = '2027-01-01';
        $tracking->checkedBy = 'Bob';
        $tracking->date = '2026-01-01';
        $model->addRiskTracking($tracking);

        $result = $this->roundTrip($model)->getRiskTracking()['abc123'];

        self::assertSame(DecisionStatus::Accepted, $result->status);
        self::assertSame('Compensating control in place, reviewed quarterly.', $result->justification);
        self::assertSame('JIRA-1', $result->ticket);
        self::assertSame('2027-01-01', $result->expiresAt);
        self::assertSame('Bob', $result->checkedBy);
        self::assertSame('2026-01-01', $result->date);
    }

    public function testRoundTripsQuestionIncludingAnswer(): void
    {
        $model = new ThreatModel('App');
        $model->addQuestion(new Question('q1', 'Was a pentest performed?', 'Not yet'));
        $model->addQuestion(new Question('q2', 'Unanswered?'));

        $result = $this->roundTrip($model);

        self::assertSame('Not yet', $result->getQuestions()['q1']->answer);
        self::assertSame('Was a pentest performed?', $result->getQuestions()['q1']->text);
        self::assertNull($result->getQuestions()['q2']->answer);
    }

    public function testAbuseCaseIdDoublesAsTitle(): void
    {
        // Documented mapping: the canonical schema's abuseCases use
        // {title, text}, our AbuseCase uses {id, description} — id <-> title.
        $model = new ThreatModel('App');
        $model->addAbuseCase(new AbuseCase('steal-data', 'Attacker exfiltrates PII'));

        $result = $this->roundTrip($model);
        self::assertEquals(
            new AbuseCase('steal-data', 'Attacker exfiltrates PII'),
            $result->getAbuseCases()['steal-data'],
        );
    }

    public function testAbuseCaseRoundTripsStructuredFields(): void
    {
        $model = new ThreatModel('App');
        $case = new AbuseCase('brute-force-login', 'Guess passwords at login');
        $case->asA = 'anonymous attacker';
        $case->iWant = 'brute-force credentials';
        $case->soThat = 'take over accounts';
        $case->actorId = 'external-attacker';
        $case->assetIds = ['web-app'];
        $case->dataFlowIds = ['browser-to-web-app'];
        $case->dataAssetIds = ['credentials'];
        $case->threatIds = ['THREAT-BRUTE-FORCE'];
        $case->requiredCwes = ['CWE-307'];
        $case->status = \HybridTM\Enums\AbuseCaseStatus::InProgress;
        $model->addAbuseCase($case);

        $result = $this->roundTrip($model);
        $got = $result->getAbuseCases()['brute-force-login'];
        self::assertSame('anonymous attacker', $got->asA);
        self::assertSame('brute-force credentials', $got->iWant);
        self::assertSame('take over accounts', $got->soThat);
        self::assertSame('external-attacker', $got->actorId);
        self::assertSame(['web-app'], $got->assetIds);
        self::assertSame(['browser-to-web-app'], $got->dataFlowIds);
        self::assertSame(['credentials'], $got->dataAssetIds);
        self::assertSame(['THREAT-BRUTE-FORCE'], $got->threatIds);
        self::assertSame(['CWE-307'], $got->requiredCwes);
        self::assertSame(\HybridTM\Enums\AbuseCaseStatus::InProgress, $got->status);
    }

    public function testSecurityRequirementRoundTrips(): void
    {
        $model = new ThreatModel('App');
        $model->addSecurityRequirement(new SecurityRequirement('firewall', 'Corporate firewall in place'));

        $result = $this->roundTrip($model);
        self::assertEquals(
            new SecurityRequirement('firewall', 'Corporate firewall in place'),
            $result->getSecurityRequirements()['firewall'],
        );
    }

    // ── kbVersion ────────────────────────────────────────────────────────────

    public function testEncodeIncludesKbVersionWhenGiven(): void
    {
        $encoded = $this->codec->encode(new ThreatModel('App'), 'kb-core@1.0.0');
        self::assertSame('kb-core@1.0.0', $encoded['kbVersion']);
    }

    public function testEncodeOmitsKbVersionWhenNotGiven(): void
    {
        $encoded = $this->codec->encode(new ThreatModel('App'));
        self::assertArrayNotHasKey('kbVersion', $encoded);
    }

    // ── whole-model round trip ───────────────────────────────────────────────

    public function testRoundTripsExampleThreatModel(): void
    {
        $model = require __DIR__ . '/../../example/threat-model.php';
        self::assertInstanceOf(ThreatModel::class, $model);

        $result = $this->roundTrip($model);

        self::assertSame($model->title, $result->title);
        self::assertSame(count($model->getTechnicalAssets()), count($result->getTechnicalAssets()));
        self::assertSame(count($model->getDataAssets()), count($result->getDataAssets()));
        self::assertSame(count($model->getTrustBoundaries()), count($result->getTrustBoundaries()));

        foreach ($model->getTechnicalAssets() as $id => $asset) {
            $decoded = $result->getTechnicalAsset($id);
            self::assertNotNull($decoded, "asset '{$id}' must survive the round trip");
            self::assertSame($asset->name, $decoded->name);
            self::assertCount(count($asset->communicationLinks), $decoded->communicationLinks);
        }
    }
}
