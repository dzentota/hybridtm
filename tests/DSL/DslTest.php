<?php
declare(strict_types=1);
namespace HybridTM\Tests\DSL;

use HybridTM\DSL\CommunicationLink;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\TrustBoundaryType;
use PHPUnit\Framework\TestCase;

final class DslTest extends TestCase
{
    // ── ThreatModel ────────────────────────────────────────────────────────────

    public function testThreatModelTitle(): void
    {
        $tm = new ThreatModel('My App');
        self::assertSame('My App', $tm->title);
    }

    public function testThreatModelDefaults(): void
    {
        $tm = new ThreatModel('App');
        self::assertSame('', $tm->description);
        self::assertSame('', $tm->author);
        self::assertSame('', $tm->date);
        self::assertSame(BusinessCriticality::Important, $tm->businessCriticality);
        self::assertSame([], $tm->getDataAssets());
        self::assertSame([], $tm->getTechnicalAssets());
        self::assertSame([], $tm->getTrustBoundaries());
    }

    public function testThreatModelAddAndGetDataAsset(): void
    {
        $tm = new ThreatModel('App');
        $da = new DataAsset('user-data', 'User Data');
        $tm->addDataAsset($da);

        self::assertSame($da, $tm->getDataAsset('user-data'));
        self::assertNull($tm->getDataAsset('nonexistent'));
        self::assertCount(1, $tm->getDataAssets());
    }

    public function testThreatModelAddAndGetTechnicalAsset(): void
    {
        $tm = new ThreatModel('App');
        $ta = new TechnicalAsset('web-api', 'Web API');
        $tm->addTechnicalAsset($ta);

        self::assertSame($ta, $tm->getTechnicalAsset('web-api'));
        self::assertNull($tm->getTechnicalAsset('nonexistent'));
    }

    public function testThreatModelAddAndGetTrustBoundary(): void
    {
        $tm = new ThreatModel('App');
        $tb = new TrustBoundary('internal-net', 'Internal Network');
        $tm->addTrustBoundary($tb);

        self::assertCount(1, $tm->getTrustBoundaries());
        self::assertSame($tb, $tm->getTrustBoundaries()['internal-net']);
    }

    public function testThreatModelAddMethodsReturnSelf(): void
    {
        $tm = new ThreatModel('App');
        self::assertSame($tm, $tm->addDataAsset(new DataAsset('d')));
        self::assertSame($tm, $tm->addTechnicalAsset(new TechnicalAsset('t')));
        self::assertSame($tm, $tm->addTrustBoundary(new TrustBoundary('b')));
    }

    public function testThreatModelAssetKeyedById(): void
    {
        $tm = new ThreatModel('App');
        $tm->addDataAsset(new DataAsset('id-a'));
        $tm->addDataAsset(new DataAsset('id-b'));
        self::assertArrayHasKey('id-a', $tm->getDataAssets());
        self::assertArrayHasKey('id-b', $tm->getDataAssets());
    }

    // ── TechnicalAsset ─────────────────────────────────────────────────────────

    public function testTechnicalAssetIdAndNameDefault(): void
    {
        $ta = new TechnicalAsset('my-svc');
        self::assertSame('my-svc', $ta->id);
        self::assertSame('my-svc', $ta->name); // name defaults to id
    }

    public function testTechnicalAssetCustomName(): void
    {
        $ta = new TechnicalAsset('my-svc', 'My Service');
        self::assertSame('My Service', $ta->name);
    }

    public function testTechnicalAssetDefaults(): void
    {
        $ta = new TechnicalAsset('svc');
        self::assertSame([], $ta->communicationLinks);
        self::assertSame([], $ta->dataAssetsProcessed);
        self::assertSame([], $ta->dataAssetsStored);
        self::assertSame(Encryption::None, $ta->encryption);
        self::assertSame(Confidentiality::Internal, $ta->confidentiality);
        self::assertFalse($ta->internet);
        self::assertFalse($ta->multiTenant);
        self::assertFalse($ta->redundant);
        self::assertFalse($ta->customDevelopedParts);
    }

    public function testTechnicalAssetCommunicatesTo(): void
    {
        $ta = new TechnicalAsset('web');
        $link = $ta->communicatesTo('db', Protocol::SqlAccessProtocol, Authentication::Credentials);

        self::assertInstanceOf(CommunicationLink::class, $link);
        self::assertSame('db', $link->targetAssetId);
        self::assertSame(Protocol::SqlAccessProtocol, $link->protocol);
        self::assertSame(Authentication::Credentials, $link->authentication);
        self::assertArrayHasKey('web-to-db', $ta->communicationLinks);
    }

    public function testTechnicalAssetCommunicatesToLinkIdFormat(): void
    {
        $ta = new TechnicalAsset('frontend');
        $link = $ta->communicatesTo('backend');
        self::assertSame('frontend-to-backend', $link->id);
    }

    public function testTechnicalAssetCommunicatesToReturnsSameInstance(): void
    {
        $ta = new TechnicalAsset('a');
        $link1 = $ta->communicatesTo('b');
        $link2 = $ta->communicatesTo('b');
        // second call overwrites the first (same linkId)
        self::assertNotSame($link1, $link2);
        self::assertCount(1, $ta->communicationLinks);
    }

    public function testTechnicalAssetCommunicatesToDescription(): void
    {
        $ta = new TechnicalAsset('svc');
        $link = $ta->communicatesTo('db', description: 'Query DB');
        self::assertSame('Query DB', $link->description);
    }

    // ── DataAsset ──────────────────────────────────────────────────────────────

    public function testDataAssetIdAndNameDefault(): void
    {
        $da = new DataAsset('session-token');
        self::assertSame('session-token', $da->id);
        self::assertSame('session-token', $da->name);
    }

    public function testDataAssetCustomName(): void
    {
        $da = new DataAsset('tok', 'Session Token');
        self::assertSame('Session Token', $da->name);
    }

    public function testDataAssetDefaults(): void
    {
        $da = new DataAsset('d');
        self::assertSame('', $da->description);
        self::assertSame(DataOrigin::Unknown, $da->origin);
        self::assertSame(Confidentiality::Internal, $da->confidentiality);
        self::assertSame([], $da->tags);
    }

    // ── CommunicationLink ──────────────────────────────────────────────────────

    public function testCommunicationLinkDefaults(): void
    {
        $link = new CommunicationLink('a-to-b', 'b');
        self::assertSame('a-to-b', $link->id);
        self::assertSame('b', $link->targetAssetId);
        self::assertSame(Protocol::Https, $link->protocol);
        self::assertSame(Authentication::None, $link->authentication);
        self::assertSame(Authorization::None, $link->authorization);
        self::assertFalse($link->vpn);
        self::assertFalse($link->ipFiltered);
        self::assertFalse($link->readonly);
        self::assertSame([], $link->dataSent);
        self::assertSame([], $link->dataReceived);
        self::assertSame([], $link->tags);
    }

    public function testCommunicationLinkMutableFields(): void
    {
        $link = new CommunicationLink('x-to-y', 'y', Protocol::BinaryEncrypted);
        $link->vpn = true;
        $link->dataSent = ['payload'];
        $link->description = 'gRPC call';

        self::assertTrue($link->vpn);
        self::assertSame(['payload'], $link->dataSent);
        self::assertSame('gRPC call', $link->description);
    }

    // ── TrustBoundary ──────────────────────────────────────────────────────────

    public function testTrustBoundaryIdAndNameDefault(): void
    {
        $tb = new TrustBoundary('dmz');
        self::assertSame('dmz', $tb->id);
        self::assertSame('dmz', $tb->name);
    }

    public function testTrustBoundaryDefaultType(): void
    {
        $tb = new TrustBoundary('net');
        self::assertSame(TrustBoundaryType::NetworkOnPrem, $tb->type);
    }

    public function testTrustBoundaryAddAssets(): void
    {
        $tb = new TrustBoundary('net');
        $result = $tb->addAssets('svc-a', 'svc-b');

        self::assertSame($tb, $result);
        self::assertContains('svc-a', $tb->technicalAssetsInside);
        self::assertContains('svc-b', $tb->technicalAssetsInside);
    }

    public function testTrustBoundaryAddAssetsNoDuplicates(): void
    {
        $tb = new TrustBoundary('net');
        $tb->addAssets('svc-a', 'svc-a', 'svc-b');
        $tb->addAssets('svc-a');

        self::assertCount(2, $tb->technicalAssetsInside);
    }
}
