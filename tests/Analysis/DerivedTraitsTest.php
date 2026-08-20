<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\DerivedTraits;
use PHPUnit\Framework\TestCase;

final class DerivedTraitsTest extends TestCase
{
    public function testForAssetIsEmptyForUnknownAsset(): void
    {
        self::assertSame([], (new DerivedTraits())->forAsset('nope'));
    }

    public function testAddThenForAssetReturnsTheTrait(): void
    {
        $traits = new DerivedTraits();
        $traits->add('web', 'internet_reachable');

        self::assertSame(['internet_reachable'], $traits->forAsset('web'));
    }

    public function testAddDoesNotDuplicateTheSameTraitTwice(): void
    {
        $traits = new DerivedTraits();
        $traits->add('web', 'internet_reachable');
        $traits->add('web', 'internet_reachable');

        self::assertSame(['internet_reachable'], $traits->forAsset('web'));
    }

    public function testAddAccumulatesDistinctTraitsInOrder(): void
    {
        $traits = new DerivedTraits();
        $traits->add('web', 'internet_reachable');
        $traits->add('web', 'behind_waf');

        self::assertSame(['internet_reachable', 'behind_waf'], $traits->forAsset('web'));
    }

    public function testTraitsAreScopedPerAsset(): void
    {
        $traits = new DerivedTraits();
        $traits->add('web', 'internet_reachable');
        $traits->add('db', 'directly_exposed_datastore');

        self::assertSame(['internet_reachable'], $traits->forAsset('web'));
        self::assertSame(['directly_exposed_datastore'], $traits->forAsset('db'));
    }
}
