<?php

declare(strict_types=1);

namespace HybridTM\Tests\Enums;

use HybridTM\Enums\Protocol;
use PHPUnit\Framework\TestCase;

final class ProtocolTest extends TestCase
{
    public function testKnownEncryptedProtocols(): void
    {
        foreach ([Protocol::Https, Protocol::Wss, Protocol::SqlAccessProtocolEncrypted, Protocol::Ssh, Protocol::Sftp, Protocol::Ldaps] as $protocol) {
            self::assertTrue($protocol->isEncrypted(), $protocol->value . ' should be encrypted');
        }
    }

    public function testKnownUnencryptedProtocolsDespiteEndingInS(): void
    {
        // Regression guard: a naive "ends with 's'" heuristic would misfire here.
        foreach ([Protocol::Nfs, Protocol::Jms] as $protocol) {
            self::assertFalse($protocol->isEncrypted(), $protocol->value . ' should not be encrypted');
        }
    }

    public function testPlainHttpIsNotEncrypted(): void
    {
        self::assertFalse(Protocol::Http->isEncrypted());
    }
}
