<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis\Rules;

use HybridTM\Analysis\Rules\PhpRuleLoader;
use HybridTM\Analysis\Rules\PhpRuleLoadException;
use HybridTM\Analysis\Rules\RuleInterface;
use HybridTM\Kb\Rules\UnguardedPathFromInternetRule;
use PHPUnit\Framework\TestCase;

final class PhpRuleLoaderTest extends TestCase
{
    public function testLoadsARealRuleClass(): void
    {
        $rule = (new PhpRuleLoader())->load(UnguardedPathFromInternetRule::class);
        self::assertInstanceOf(RuleInterface::class, $rule);
    }

    public function testThrowsForNonexistentClass(): void
    {
        $this->expectException(PhpRuleLoadException::class);
        (new PhpRuleLoader())->load('HybridTM\\Nonexistent\\ClassName');
    }

    public function testThrowsForClassNotImplementingRuleInterface(): void
    {
        $this->expectException(PhpRuleLoadException::class);
        (new PhpRuleLoader())->load(\stdClass::class);
    }
}
