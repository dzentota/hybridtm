<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\RuleExpressionException;
use HybridTM\Analysis\RuleExpressionProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

final class RuleExpressionProviderTest extends TestCase
{
    private RuleExpressionProvider $provider;

    protected function setUp(): void
    {
        if (!class_exists(ExpressionLanguage::class)) {
            self::markTestSkipped('symfony/expression-language is not installed.');
        }
        $this->provider = new RuleExpressionProvider();
    }

    public function testEvaluatesLiteralBoolean(): void
    {
        self::assertTrue($this->provider->evaluate('true', []));
        self::assertFalse($this->provider->evaluate('false', []));
    }

    public function testEvaluatesMethodCallOnContextObject(): void
    {
        $subject = new class () {
            public function hasTrait(string $t): bool
            {
                return $t === 'datastore';
            }
        };

        self::assertTrue($this->provider->evaluate("component.hasTrait('datastore')", ['component' => $subject]));
        self::assertFalse($this->provider->evaluate("component.hasTrait('other')", ['component' => $subject]));
    }

    public function testEvaluatesPublicPropertyAccess(): void
    {
        $subject = new class () {
            public bool $internet = true;
        };
        self::assertTrue($this->provider->evaluate('component.internet', ['component' => $subject]));
    }

    public function testEvaluatesChainedPropertyThenMethod(): void
    {
        $props = new class () {
            public function bool(string $k): bool
            {
                return $k === 'internet_facing';
            }
        };
        $subject = new class ($props) {
            public function __construct(public object $props)
            {
            }
        };

        self::assertTrue($this->provider->evaluate("component.props.bool('internet_facing')", ['component' => $subject]));
    }

    public function testMalformedExpressionThrows(): void
    {
        $this->expectException(RuleExpressionException::class);
        $this->provider->evaluate('this is not valid syntax )))', []);
    }

    public function testUndefinedMethodThrows(): void
    {
        $subject = new class () {};
        $this->expectException(RuleExpressionException::class);
        $this->provider->evaluate('component.nonexistentMethod()', ['component' => $subject]);
    }

    public function testRenderLeavesPlainTextUnchanged(): void
    {
        self::assertSame('plain text, no braces', $this->provider->render('plain text, no braces', []));
    }

    public function testRenderSubstitutesExpression(): void
    {
        $subject = new class () {
            public string $name = 'Nginx';
        };
        self::assertSame(
            'Component Nginx is affected',
            $this->provider->render('Component {{ component.name }} is affected', ['component' => $subject]),
        );
    }

    public function testRenderSupportsTernary(): void
    {
        $subject = new class () {
            public function isCritical(): bool
            {
                return true;
            }
        };
        self::assertSame(
            'high',
            $this->provider->render("{{ component.isCritical() ? 'high' : 'medium' }}", ['component' => $subject]),
        );
    }

    public function testRenderSubstitutesMultiplePlaceholders(): void
    {
        $subject = new class () {
            public string $name = 'A';
            public string $encryption = 'none';
        };
        self::assertSame(
            'A has encryption none',
            $this->provider->render('{{ component.name }} has encryption {{ component.encryption }}', ['component' => $subject]),
        );
    }
}
