<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\CodeLocation;
use PHPUnit\Framework\TestCase;

final class CodeLocationTest extends TestCase
{
    public function testToStringFormatsFileAndLine(): void
    {
        $location = new CodeLocation('src/Foo.php', 42);

        self::assertSame('src/Foo.php:42', (string) $location);
    }

    public function testJsonSerializeIncludesAllFields(): void
    {
        $location = new CodeLocation('src/Foo.php', 42, 'App\\Foo', 'save');

        self::assertSame([
            'file' => 'src/Foo.php',
            'line' => 42,
            'class' => 'App\\Foo',
            'method' => 'save',
        ], $location->jsonSerialize());
    }

    public function testClassAndMethodDefaultToNull(): void
    {
        $location = new CodeLocation('src/Foo.php', 1);

        self::assertNull($location->class);
        self::assertNull($location->method);
        self::assertNull($location->jsonSerialize()['class']);
        self::assertNull($location->jsonSerialize()['method']);
    }
}
