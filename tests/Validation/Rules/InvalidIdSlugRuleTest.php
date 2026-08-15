<?php
declare(strict_types=1);
namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Validation\Rules\InvalidIdSlugRule;
use PHPUnit\Framework\TestCase;

final class InvalidIdSlugRuleTest extends TestCase
{
    private InvalidIdSlugRule $rule;

    protected function setUp(): void
    {
        $this->rule = new InvalidIdSlugRule();
    }

    public function testFlagsUppercaseId(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('WebApp'));

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testFlagsIdStartingWithDigit(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('1-web'));

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testFlagsIdWithUnderscore(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web_app'));

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testPassesValidSlug(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web-app-01'));

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
