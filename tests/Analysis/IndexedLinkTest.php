<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\IndexedLink;
use HybridTM\DSL\CommunicationLink;
use HybridTM\Enums\Protocol;
use PHPUnit\Framework\TestCase;

final class IndexedLinkTest extends TestCase
{
    public function testTargetAssetIdIsDerivedFromTheLink(): void
    {
        $link = new CommunicationLink('web-to-db', 'db', Protocol::JdbcEncrypted);
        $indexed = new IndexedLink('web', $link);

        self::assertSame('web', $indexed->sourceAssetId);
        self::assertSame('db', $indexed->targetAssetId);
        self::assertSame($link, $indexed->link);
    }
}
