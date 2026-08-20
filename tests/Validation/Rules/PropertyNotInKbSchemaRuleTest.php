<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Tests\Validation\FakeKnowledgeBase;
use HybridTM\Validation\Rules\PropertyNotInKbSchemaRule;
use PHPUnit\Framework\TestCase;

final class PropertyNotInKbSchemaRuleTest extends TestCase
{
    private PropertyNotInKbSchemaRule $rule;

    protected function setUp(): void
    {
        $this->rule = new PropertyNotInKbSchemaRule();
    }

    private function kbWithNginx(): FakeKnowledgeBase
    {
        return (new FakeKnowledgeBase())->withComponent('web-server-nginx', [
            'properties' => [
                ['id' => 'internet_facing'],
                ['id' => 'tls_terminated'],
            ],
        ]);
    }

    public function testFlagsPropertyNotInSchema(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->tags = ['kb-component:web-server-nginx'];
        $web->properties->set('unknown_prop', true);
        $model->addTechnicalAsset($web);

        $issues = iterator_to_array($this->rule->check($model, $this->kbWithNginx()));
        self::assertCount(1, $issues);
        self::assertStringContainsString('unknown_prop', $issues[0]->message);
    }

    public function testPassesForDeclaredProperty(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->tags = ['kb-component:web-server-nginx'];
        $web->properties->set('internet_facing', true);
        $model->addTechnicalAsset($web);

        self::assertSame([], iterator_to_array($this->rule->check($model, $this->kbWithNginx())));
    }

    public function testSilentWithoutKnowledgeBase(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->tags = ['kb-component:web-server-nginx'];
        $web->properties->set('unknown_prop', true);
        $model->addTechnicalAsset($web);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testSilentWithoutMarkerTag(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->properties->set('unknown_prop', true);
        $model->addTechnicalAsset($web);

        self::assertSame([], iterator_to_array($this->rule->check($model, $this->kbWithNginx())));
    }
}
