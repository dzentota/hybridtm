<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\CodeLocation;
use HybridTM\Analysis\MitigationEvidence;
use HybridTM\Enums\MitigationStatus;
use PHPUnit\Framework\TestCase;

final class MitigationEvidenceTest extends TestCase
{
    public function testJsonSerializeIncludesAllFields(): void
    {
        $location = new CodeLocation('src/Foo.php', 10);
        $evidence = new MitigationEvidence('CWE-89', 'Parameterized queries', MitigationStatus::Mitigated, $location);

        self::assertSame([
            'cwe' => 'CWE-89',
            'description' => 'Parameterized queries',
            'status' => MitigationStatus::Mitigated->value,
            'location' => $location,
        ], $evidence->jsonSerialize());
    }

    public function testLocationDefaultsToNull(): void
    {
        $evidence = new MitigationEvidence('CWE-89', 'desc', MitigationStatus::Mitigated);

        self::assertNull($evidence->location);
        self::assertNull($evidence->jsonSerialize()['location']);
    }
}
