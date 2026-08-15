<?php
declare(strict_types=1);
namespace HybridTM\Tests\Enums;

use HybridTM\Enums\Confidentiality;
use PHPUnit\Framework\TestCase;

final class ConfidentialityTest extends TestCase
{
    public function testRankOrdering(): void
    {
        self::assertTrue(Confidentiality::StrictlyConfidential->rank() > Confidentiality::Confidential->rank());
        self::assertTrue(Confidentiality::Confidential->rank() > Confidentiality::Restricted->rank());
        self::assertTrue(Confidentiality::Restricted->rank() > Confidentiality::Internal->rank());
        self::assertTrue(Confidentiality::Internal->rank() > Confidentiality::Public->rank());
    }

    public function testIsAtLeast(): void
    {
        self::assertTrue(Confidentiality::Confidential->isAtLeast(Confidentiality::Internal));
        self::assertTrue(Confidentiality::Confidential->isAtLeast(Confidentiality::Confidential));
        self::assertFalse(Confidentiality::Internal->isAtLeast(Confidentiality::Confidential));
    }

    public function testAlphabeticalOrderWouldHaveBeenWrong(): void
    {
        // Documents exactly why rank() exists instead of comparing ->value.
        self::assertTrue('confidential' < 'internal');
        self::assertTrue(Confidentiality::Confidential->rank() > Confidentiality::Internal->rank());
    }
}
