<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\StandardsMapping;
use PHPUnit\Framework\TestCase;

final class StandardsMappingTest extends TestCase
{
    public function testHasCweIsTrueOnlyForListedCwes(): void
    {
        $mapping = new StandardsMapping(cwe: [311, 312]);

        self::assertTrue($mapping->hasCwe(311));
        self::assertTrue($mapping->hasCwe(312));
        self::assertFalse($mapping->hasCwe(89));
    }

    public function testHasCweIsFalseWhenEmpty(): void
    {
        self::assertFalse((new StandardsMapping())->hasCwe(311));
    }

    public function testJsonSerializeOmitsEmptyFields(): void
    {
        $mapping = new StandardsMapping(cwe: [311], owaspAsvs: ['V6.2.1']);

        $json = $mapping->jsonSerialize();

        self::assertSame(['cwe' => [311], 'owaspAsvs' => ['V6.2.1']], $json);
        self::assertArrayNotHasKey('capec', $json);
        self::assertArrayNotHasKey('mitreAttack', $json);
    }

    public function testJsonSerializeIsEmptyArrayWhenAllFieldsAreEmpty(): void
    {
        self::assertSame([], (new StandardsMapping())->jsonSerialize());
    }

    public function testJsonSerializeIncludesAllPopulatedFields(): void
    {
        $mapping = new StandardsMapping(
            cwe: [311],
            capec: [37],
            owaspTop10: ['A02'],
            owaspAsvs: ['V6.2.1'],
            mitreAttack: ['T1005'],
            pciDss: ['3.5.1'],
            iso27001: ['A.8.24'],
            nist80053: ['SC-28'],
        );

        $json = $mapping->jsonSerialize();

        self::assertSame([311], $json['cwe']);
        self::assertSame([37], $json['capec']);
        self::assertSame(['A02'], $json['owaspTop10']);
        self::assertSame(['V6.2.1'], $json['owaspAsvs']);
        self::assertSame(['T1005'], $json['mitreAttack']);
        self::assertSame(['3.5.1'], $json['pciDss']);
        self::assertSame(['A.8.24'], $json['iso27001']);
        self::assertSame(['SC-28'], $json['nist80053']);
    }
}
