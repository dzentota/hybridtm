<?php
declare(strict_types=1);
namespace HybridTM\Tests\Attributes;

use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;
use HybridTM\Attributes\Mitigation;
use HybridTM\Attributes\ProcessesData;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;
use PHPUnit\Framework\TestCase;

final class AttributesTest extends TestCase
{
    public function testAssetIdStoresId(): void
    {
        $attr = new AssetId('my-service');
        self::assertSame('my-service', $attr->id);
    }

    public function testAssetIdIsReadonly(): void
    {
        $attr = new AssetId('svc');
        $ref = new \ReflectionProperty($attr, 'id');
        self::assertTrue($ref->isReadOnly());
    }

    public function testDataFlowDefaultValues(): void
    {
        $attr = new DataFlow('target-asset');
        self::assertSame('target-asset', $attr->target);
        self::assertSame(Protocol::Https, $attr->protocol);
        self::assertSame(Authentication::None, $attr->authentication);
        self::assertSame(Authorization::None, $attr->authorization);
        self::assertSame([], $attr->dataSent);
        self::assertSame([], $attr->dataReceived);
        self::assertFalse($attr->vpn);
        self::assertFalse($attr->ipFiltered);
        self::assertFalse($attr->readonly);
    }

    public function testDataFlowCustomValues(): void
    {
        $attr = new DataFlow(
            target: 'db',
            protocol: Protocol::SqlAccessProtocol,
            authentication: Authentication::Credentials,
            authorization: Authorization::TechnicalUser,
            dataSent: ['user-data'],
            dataReceived: ['query-result'],
            vpn: true,
            ipFiltered: true,
            readonly: true,
        );

        self::assertSame('db', $attr->target);
        self::assertSame(Protocol::SqlAccessProtocol, $attr->protocol);
        self::assertSame(Authentication::Credentials, $attr->authentication);
        self::assertSame(Authorization::TechnicalUser, $attr->authorization);
        self::assertSame(['user-data'], $attr->dataSent);
        self::assertSame(['query-result'], $attr->dataReceived);
        self::assertTrue($attr->vpn);
        self::assertTrue($attr->ipFiltered);
        self::assertTrue($attr->readonly);
    }

    public function testMitigationDefaultStatus(): void
    {
        $attr = new Mitigation('CWE-89', 'Use prepared statements');
        self::assertSame('CWE-89', $attr->cwe);
        self::assertSame('Use prepared statements', $attr->description);
        self::assertSame(MitigationStatus::Mitigated, $attr->status);
    }

    public function testMitigationCustomStatus(): void
    {
        $attr = new Mitigation('CWE-79', 'Sanitize output', MitigationStatus::InProgress);
        self::assertSame(MitigationStatus::InProgress, $attr->status);
    }

    public function testProcessesDataStoresAssetIds(): void
    {
        $attr = new ProcessesData(['user-pii', 'session-data']);
        self::assertSame(['user-pii', 'session-data'], $attr->dataAssets);
    }

    public function testProcessesDataEmptyList(): void
    {
        $attr = new ProcessesData([]);
        self::assertSame([], $attr->dataAssets);
    }

    public function testAttributeTargetConstantsAreCorrect(): void
    {
        $assetId = new \ReflectionClass(AssetId::class);
        $attrs = $assetId->getAttributes(\Attribute::class);
        self::assertCount(1, $attrs);
        $flags = $attrs[0]->newInstance()->flags;
        self::assertSame(\Attribute::TARGET_CLASS, $flags);

        $dataFlow = new \ReflectionClass(DataFlow::class);
        $attrs = $dataFlow->getAttributes(\Attribute::class);
        $flags = $attrs[0]->newInstance()->flags;
        self::assertTrue((bool)($flags & \Attribute::IS_REPEATABLE));

        $mitigation = new \ReflectionClass(Mitigation::class);
        $attrs = $mitigation->getAttributes(\Attribute::class);
        $flags = $attrs[0]->newInstance()->flags;
        self::assertTrue((bool)($flags & \Attribute::IS_REPEATABLE));
    }
}
