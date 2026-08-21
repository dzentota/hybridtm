<?php

declare(strict_types=1);

namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Validation\Rules\DanglingCommunicationLinkTargetRule;
use PHPUnit\Framework\TestCase;

final class DanglingCommunicationLinkTargetRuleTest extends TestCase
{
    private DanglingCommunicationLinkTargetRule $rule;

    protected function setUp(): void
    {
        $this->rule = new DanglingCommunicationLinkTargetRule();
    }

    public function testFlagsLinkToUnknownAsset(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('nonexistent-db');
        $model->addTechnicalAsset($web);

        $issues = iterator_to_array($this->rule->check($model, null));

        self::assertCount(1, $issues);
        self::assertStringContainsString('nonexistent-db', $issues[0]->message);
    }

    public function testPassesWhenTargetExists(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
