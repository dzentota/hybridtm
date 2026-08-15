<?php
declare(strict_types=1);
namespace HybridTM\Tests\Enums;

use HybridTM\Enums\Technology;
use HybridTM\Enums\TechnologyList;
use PHPUnit\Framework\TestCase;

final class TechnologyListTest extends TestCase
{
    public function testEmptyByDefault(): void
    {
        $list = new TechnologyList();
        self::assertCount(0, $list);
        self::assertSame([], $list->values());
    }

    public function testAddEnumCase(): void
    {
        $list = new TechnologyList();
        $list->add(Technology::ReverseProxy);
        self::assertSame(['reverse-proxy'], $list->values());
    }

    public function testAddCustomString(): void
    {
        $list = new TechnologyList();
        $list->add('load-balancer');
        self::assertSame(['load-balancer'], $list->values());
    }

    public function testAddIsIdempotent(): void
    {
        $list = new TechnologyList();
        $list->add(Technology::ReverseProxy)->add(Technology::ReverseProxy)->add('reverse-proxy');
        self::assertCount(1, $list, 'enum case and its string value are the same technology');
    }

    public function testAddReturnsSelfForChaining(): void
    {
        $list = new TechnologyList();
        self::assertSame($list, $list->add(Technology::WebServer));
    }

    public function testValuesPreservesInsertionOrder(): void
    {
        $list = new TechnologyList();
        $list->add(Technology::ReverseProxy)->add(Technology::WebServer)->add('load-balancer');
        self::assertSame(['reverse-proxy', 'web-server', 'load-balancer'], $list->values());
    }

    public function testContains(): void
    {
        $list = new TechnologyList([Technology::Database]);
        self::assertTrue($list->contains(Technology::Database));
        self::assertTrue($list->contains('database'));
        self::assertFalse($list->contains(Technology::WebServer));
    }

    public function testPrimaryReturnsFirstKnownTechnology(): void
    {
        $list = new TechnologyList(['custom-thing', Technology::ReverseProxy, Technology::WebServer]);
        self::assertSame(Technology::ReverseProxy, $list->primary());
    }

    public function testPrimaryFallsBackToUnknownForCustomOnlyList(): void
    {
        $list = new TechnologyList(['acme-proprietary-bus']);
        self::assertSame(Technology::Unknown, $list->primary());
    }

    public function testPrimaryOnEmptyListIsUnknown(): void
    {
        self::assertSame(Technology::Unknown, (new TechnologyList())->primary());
    }

    public function testIterable(): void
    {
        $list = new TechnologyList([Technology::ReverseProxy, 'load-balancer']);
        self::assertSame([Technology::ReverseProxy, 'load-balancer'], iterator_to_array($list));
    }

    public function testConstructFromArrayDeduplicates(): void
    {
        $list = new TechnologyList([Technology::WebServer, Technology::WebServer]);
        self::assertCount(1, $list);
    }
}
