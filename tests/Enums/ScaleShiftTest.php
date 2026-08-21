<?php

declare(strict_types=1);

namespace HybridTM\Tests\Enums;

use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use PHPUnit\Framework\TestCase;

/** Scoring modifiers shift these scales; they must clamp, never wrap or overflow. */
final class ScaleShiftTest extends TestCase
{
    public function testLikelihoodClampsAtBothEnds(): void
    {
        self::assertSame(Likelihood::Unlikely, Likelihood::Unlikely->shift(-5));
        self::assertSame(Likelihood::Frequent, Likelihood::Frequent->shift(5));
        self::assertSame(Likelihood::VeryLikely, Likelihood::Likely->shift(1));
        self::assertSame(Likelihood::Unlikely, Likelihood::Likely->shift(-1));
        self::assertSame(Likelihood::Likely, Likelihood::Likely->shift(0));
    }

    public function testImpactClampsAtBothEnds(): void
    {
        self::assertSame(Impact::Low, Impact::Low->shift(-3));
        self::assertSame(Impact::VeryHigh, Impact::VeryHigh->shift(3));
        self::assertSame(Impact::High, Impact::Medium->shift(1));
        self::assertSame(Impact::Low, Impact::Medium->shift(-1));
    }
}
