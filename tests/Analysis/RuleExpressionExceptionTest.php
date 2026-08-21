<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\RuleExpressionException;
use PHPUnit\Framework\TestCase;

final class RuleExpressionExceptionTest extends TestCase
{
    public function testIsARuntimeException(): void
    {
        $exception = new RuleExpressionException('bad expression');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame('bad expression', $exception->getMessage());
    }
}
