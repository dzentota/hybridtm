<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\ConditionResult;
use PHPUnit\Framework\TestCase;

final class ConditionResultTest extends TestCase
{
    public function testDefaultsToWhenKindAndEmptyDetail(): void
    {
        $condition = new ConditionResult('component.internet == true', true);

        self::assertSame(ConditionResult::KIND_WHEN, $condition->kind);
        self::assertSame('', $condition->detail);
    }

    public function testJsonSerializeIncludesAllFields(): void
    {
        $condition = new ConditionResult('a == b', false, ConditionResult::KIND_UNLESS, 'mismatch');

        self::assertSame([
            'expression' => 'a == b',
            'passed' => false,
            'kind' => ConditionResult::KIND_UNLESS,
            'detail' => 'mismatch',
        ], $condition->jsonSerialize());
    }

    public function testKindConstantsAreDistinct(): void
    {
        self::assertNotSame(ConditionResult::KIND_WHEN, ConditionResult::KIND_UNLESS);
        self::assertSame('when', ConditionResult::KIND_WHEN);
        self::assertSame('unless', ConditionResult::KIND_UNLESS);
    }
}
