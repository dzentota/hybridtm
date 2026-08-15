<?php
declare(strict_types=1);
namespace HybridTM\Tests\DSL;

use HybridTM\DSL\PropertyBag;
use PHPUnit\Framework\TestCase;

final class PropertyBagTest extends TestCase
{
    public function testSetAndGet(): void
    {
        $bag = new PropertyBag();
        $bag->set('internet_facing', true);

        self::assertTrue($bag->has('internet_facing'));
        self::assertTrue($bag->get('internet_facing'));
    }

    public function testGetMissingReturnsDefault(): void
    {
        $bag = new PropertyBag();
        self::assertNull($bag->get('missing'));
        self::assertSame('fallback', $bag->get('missing', 'fallback'));
        self::assertFalse($bag->has('missing'));
    }

    public function testSetReturnsSelfForChaining(): void
    {
        $bag = new PropertyBag();
        self::assertSame($bag, $bag->set('a', 1));
    }

    public function testConstructFromArray(): void
    {
        $bag = new PropertyBag(['tls_min_version' => '1.2', 'hsts_enabled' => false]);

        self::assertSame('1.2', $bag->get('tls_min_version'));
        self::assertFalse($bag->get('hsts_enabled'));
        self::assertCount(2, $bag);
    }

    public function testTypeSafeAccessors(): void
    {
        $bag = new PropertyBag();
        $bag->set('enabled', true);
        $bag->set('version', '1.27.0');
        $bag->set('max_connections', 100);

        self::assertTrue($bag->bool('enabled'));
        self::assertSame('1.27.0', $bag->string('version'));
        self::assertSame(100, $bag->int('max_connections'));
    }

    public function testTypeSafeAccessorsFallBackOnTypeMismatch(): void
    {
        $bag = new PropertyBag();
        $bag->set('version', '1.27.0');

        self::assertFalse($bag->bool('version'));
        self::assertSame(0, $bag->int('version'), 'non-numeric string does not coerce to int');
        self::assertSame('', $bag->string('missing'));
    }

    public function testIntAccessorCoercesNumericString(): void
    {
        $bag = new PropertyBag(['port' => '8443']);
        self::assertSame(8443, $bag->int('port'));
    }

    public function testStringAccessorCoercesScalars(): void
    {
        $bag = new PropertyBag(['count' => 3, 'enabled' => true]);
        self::assertSame('3', $bag->string('count'));
        self::assertSame('1', $bag->string('enabled'));
    }

    public function testArrayOfScalarsIsAccepted(): void
    {
        $bag = new PropertyBag();
        $bag->set('allowed_origins', ['a.example.com', 'b.example.com']);

        self::assertSame(['a.example.com', 'b.example.com'], $bag->get('allowed_origins'));
    }

    public function testNestedArrayIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new PropertyBag())->set('bad', ['nested' => ['too', 'deep']]);
    }

    public function testObjectValueIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new PropertyBag())->set('bad', new \stdClass());
    }

    public function testNullValueIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new PropertyBag())->set('bad', null);
    }

    public function testCountReflectsNumberOfKeys(): void
    {
        $bag = new PropertyBag();
        self::assertCount(0, $bag);

        $bag->set('a', 1)->set('b', 2);
        self::assertCount(2, $bag);
    }

    public function testToArrayAndJsonSerializeMatch(): void
    {
        $bag = new PropertyBag(['a' => 1, 'b' => 'two']);

        self::assertSame($bag->toArray(), $bag->jsonSerialize());
        self::assertSame(
            '{"a":1,"b":"two"}',
            json_encode($bag, JSON_THROW_ON_ERROR),
        );
    }
}
