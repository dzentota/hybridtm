<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\SubjectKind;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class SubjectRefTest extends TestCase
{
    public function testComponentRoundTrip(): void
    {
        $ref = SubjectRef::component('user-db');

        self::assertSame('component:user-db', (string) $ref);
        self::assertEquals($ref, SubjectRef::parse((string) $ref));
        self::assertSame(SubjectKind::Component, $ref->kind);
    }

    public function testFlowRoundTrip(): void
    {
        $ref = SubjectRef::flow('web-app', 'user-db');

        self::assertSame('flow:web-app->user-db', (string) $ref);
        self::assertEquals($ref, SubjectRef::parse((string) $ref));
        self::assertSame('web-app', $ref->primaryId);
        self::assertSame('user-db', $ref->secondaryId);
    }

    public function testAllKindsRoundTrip(): void
    {
        $refs = [
            SubjectRef::component('a'),
            SubjectRef::flow('a', 'b'),
            SubjectRef::boundary('vpc'),
            SubjectRef::dataAsset('customer-pii'),
            SubjectRef::model(),
        ];

        foreach ($refs as $ref) {
            self::assertEquals($ref, SubjectRef::parse((string) $ref), (string) $ref);
        }
    }

    public function testJsonSerializesToString(): void
    {
        self::assertSame('"component:user-db"', json_encode(SubjectRef::component('user-db')));
    }

    public function testRejectsMalformedRef(): void
    {
        $this->expectException(InvalidArgumentException::class);
        SubjectRef::parse('nonsense');
    }

    public function testRejectsUnknownKind(): void
    {
        $this->expectException(InvalidArgumentException::class);
        SubjectRef::parse('gizmo:thing');
    }
}
