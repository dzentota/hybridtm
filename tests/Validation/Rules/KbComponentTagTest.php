<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\Validation\Rules\KbComponentTag;
use PHPUnit\Framework\TestCase;

final class KbComponentTagTest extends TestCase
{
    public function testParsesIdOnly(): void
    {
        $ref = KbComponentTag::fromTags(['web', 'kb-component:web-server-nginx']);
        self::assertNotNull($ref, 'Expected a kb-component tag to be found.');
        self::assertSame('web-server-nginx', $ref->componentId);
        self::assertNull($ref->version);
    }

    public function testParsesIdAndVersion(): void
    {
        $ref = KbComponentTag::fromTags(['kb-component:web-server-nginx@1.4.0']);
        self::assertNotNull($ref, 'Expected a kb-component tag to be found.');
        self::assertSame('web-server-nginx', $ref->componentId);
        self::assertSame('1.4.0', $ref->version);
    }

    public function testReturnsNullWithoutMarkerTag(): void
    {
        self::assertNull(KbComponentTag::fromTags(['web', 'prod']));
    }

    public function testReturnsNullForEmptyTags(): void
    {
        self::assertNull(KbComponentTag::fromTags([]));
    }
}
