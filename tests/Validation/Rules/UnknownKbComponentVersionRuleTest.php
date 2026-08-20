<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Tests\Validation\FakeKnowledgeBase;
use HybridTM\Validation\Rules\UnknownKbComponentVersionRule;
use PHPUnit\Framework\TestCase;

final class UnknownKbComponentVersionRuleTest extends TestCase
{
    private UnknownKbComponentVersionRule $rule;

    protected function setUp(): void
    {
        $this->rule = new UnknownKbComponentVersionRule();
    }

    public function testFlagsUnknownComponent(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->tags = ['kb-component:nonexistent-component'];
        $model->addTechnicalAsset($web);

        $issues = iterator_to_array($this->rule->check($model, new FakeKnowledgeBase()));
        self::assertCount(1, $issues);
    }

    public function testFlagsStaleVersion(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->tags = ['kb-component:web-server-nginx@1.0.0'];
        $model->addTechnicalAsset($web);

        $kb = (new FakeKnowledgeBase())->withComponent('web-server-nginx', ['metadata' => ['version' => '1.4.0']]);

        $issues = iterator_to_array($this->rule->check($model, $kb));
        self::assertCount(1, $issues);
        self::assertStringContainsString('1.4.0', $issues[0]->message);
    }

    public function testPassesForMatchingVersion(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->tags = ['kb-component:web-server-nginx@1.4.0'];
        $model->addTechnicalAsset($web);

        $kb = (new FakeKnowledgeBase())->withComponent('web-server-nginx', ['metadata' => ['version' => '1.4.0']]);

        self::assertSame([], iterator_to_array($this->rule->check($model, $kb)));
    }

    public function testSilentWithoutKnowledgeBase(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->tags = ['kb-component:nonexistent-component'];
        $model->addTechnicalAsset($web);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testSilentWithoutMarkerTag(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));

        self::assertSame([], iterator_to_array($this->rule->check($model, new FakeKnowledgeBase())));
    }
}
