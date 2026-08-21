<?php

declare(strict_types=1);

namespace HybridTM\Tests\Threagile;

use HybridTM\Threagile\MergeStrategy;
use HybridTM\Threagile\ThreagileCategoryMap;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ThreagileCategoryMapTest extends TestCase
{
    private ThreagileCategoryMap $map;

    protected function setUp(): void
    {
        $this->map = new ThreagileCategoryMap();
    }

    public function testCoversExactlyAllFortyTwoBuiltInCategories(): void
    {
        // Pinned per §5.4's full mapping table. If Threagile adds a 43rd
        // built-in rule, this count staying at 42 is what should prompt
        // someone to add a row here — see unknownCategories() below for how
        // a live analysis run would actually surface that gap.
        self::assertCount(42, $this->map->knownCategories());
    }

    public function testEveryKnownCategoryHasAStrategy(): void
    {
        foreach ($this->map->knownCategories() as $category) {
            self::assertInstanceOf(MergeStrategy::class, $this->map->strategyFor($category));
        }
    }

    /** @return iterable<string, array{0: string, 1: string|null, 2: MergeStrategy}> */
    public static function sampleCategories(): iterable
    {
        yield 'merge: unencrypted-asset' => ['unencrypted-asset', 'THREAT-DATA-AT-REST-UNENCRYPTED', MergeStrategy::Merge];
        yield 'merge: cross-site-scripting' => ['cross-site-scripting', 'THREAT-XSS', MergeStrategy::Merge];
        yield 'merge: xml-external-entity' => ['xml-external-entity', 'THREAT-XXE', MergeStrategy::Merge];
        yield 'threagile-only: mixed-targets-on-shared-runtime' => ['mixed-targets-on-shared-runtime', 'THREAT-SHARED-RUNTIME-MIXED-TRUST', MergeStrategy::ThreagileOnly];
        yield 'threagile-only: missing-identity-store' => ['missing-identity-store', 'THREAT-NO-IDENTITY-STORE', MergeStrategy::ThreagileOnly];
        yield 'validation: incomplete-model' => ['incomplete-model', null, MergeStrategy::ValidationOnly];
        yield 'validation: unnecessary-technical-asset' => ['unnecessary-technical-asset', null, MergeStrategy::ValidationOnly];
        yield 'validation: wrong-trust-boundary-content' => ['wrong-trust-boundary-content', null, MergeStrategy::ValidationOnly];
    }

    #[DataProvider('sampleCategories')]
    public function testMapsKnownCategoriesCorrectly(string $category, ?string $expectedThreatId, MergeStrategy $expectedStrategy): void
    {
        self::assertTrue($this->map->isKnown($category));
        self::assertSame($expectedThreatId, $this->map->threatIdFor($category));
        self::assertSame($expectedStrategy, $this->map->strategyFor($category));
    }

    public function testValidationOnlyCategoriesHaveNoThreatId(): void
    {
        foreach ($this->map->knownCategories() as $category) {
            if ($this->map->strategyFor($category) === MergeStrategy::ValidationOnly) {
                self::assertNull($this->map->threatIdFor($category), "{$category} is validation-only and must not carry a threat id");
            } else {
                self::assertNotNull($this->map->threatIdFor($category), "{$category} is a risk category and must carry a threat id");
            }
        }
    }

    public function testUnknownCategoryIsNotKnown(): void
    {
        self::assertFalse($this->map->isKnown('some-future-threagile-rule'));
        self::assertNull($this->map->threatIdFor('some-future-threagile-rule'));
    }

    public function testUnknownCategoryDefaultsToThreagileOnlyStrategy(): void
    {
        // Fail safe: an unrecognized category is treated as "import as-is",
        // not silently discarded and not double-counted against a guess.
        self::assertSame(MergeStrategy::ThreagileOnly, $this->map->strategyFor('some-future-threagile-rule'));
    }

    public function testUnknownCategoriesDetectsWhatIsNotMapped(): void
    {
        $seen = ['unencrypted-asset', 'cross-site-scripting', 'a-brand-new-category'];
        self::assertSame(['a-brand-new-category'], $this->map->unknownCategories($seen));
    }

    public function testUnknownCategoriesIsEmptyWhenEverythingIsMapped(): void
    {
        self::assertSame([], $this->map->unknownCategories(['unencrypted-asset', 'cross-site-scripting']));
    }

    public function testThreatIdsFollowTheThreatNamingConvention(): void
    {
        foreach ($this->map->knownCategories() as $category) {
            $threatId = $this->map->threatIdFor($category);
            if ($threatId !== null) {
                self::assertStringStartsWith('THREAT-', $threatId);
            }
        }
    }

    public function testNoTwoCategoriesShareTheSameThreatId(): void
    {
        $threatIds = array_filter(array_map(
            fn (string $c) => $this->map->threatIdFor($c),
            $this->map->knownCategories(),
        ));
        self::assertCount(count($threatIds), array_unique($threatIds), 'each threat id should come from exactly one Threagile category');
    }
}
