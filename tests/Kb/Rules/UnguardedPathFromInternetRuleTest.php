<?php
declare(strict_types=1);
namespace HybridTM\Tests\Kb\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\Rules\RuleContext;
use HybridTM\Analysis\Rules\RuleContextGraph;
use HybridTM\Analysis\Rules\RuleContextModel;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\InMemoryKnowledgeBase;
use HybridTM\Kb\Kind;
use HybridTM\Kb\Rules\UnguardedPathFromInternetRule;
use PHPUnit\Framework\TestCase;

final class UnguardedPathFromInternetRuleTest extends TestCase
{
    private function kb(): InMemoryKnowledgeBase
    {
        return new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-UNGUARDED-DATASTORE-EXPOSURE' => [
                    'title' => 'Unguarded datastore exposure',
                    'summary' => 'summary',
                    'stride' => ['information-disclosure'],
                    'countermeasures' => [],
                    'metadata' => ['id' => 'THREAT-UNGUARDED-DATASTORE-EXPOSURE'],
                ],
            ],
        ], 'test-kb');
    }

    /** @param array<string, mixed> $config */
    private function evaluate(ThreatModel $model, array $config = []): array
    {
        $index = ModelIndex::build($model);
        $derived = new DerivedTraits();
        $ctx = new RuleContext(
            'topology/unguarded-path-from-internet',
            new RuleContextModel($model, $derived),
            new RuleContextGraph($model, $index, $derived),
            $this->kb(),
            $config,
        );

        return iterator_to_array((new UnguardedPathFromInternetRule())->evaluate($ctx), false);
    }

    public function testFlagsUnguardedPathToStrictlyConfidentialDatastore(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('db');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        $findings = $this->evaluate($model);

        self::assertCount(1, $findings);
        self::assertSame('THREAT-UNGUARDED-DATASTORE-EXPOSURE', $findings[0]->threatId);
        self::assertSame('component:db', (string) $findings[0]->subject);
        self::assertStringContainsString('web -> db', $findings[0]->evidence[0]);
        self::assertSame(['CM-WAF', 'CM-NETWORK-SEGMENTATION'], $findings[0]->countermeasureIds);
    }

    public function testNoFindingWhenPathIsGuarded(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('waf');
        $waf = new TechnicalAsset('waf');
        $waf->traits = ['waf'];
        $waf->communicatesTo('db');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($web)->addTechnicalAsset($waf)->addTechnicalAsset($db);

        self::assertSame([], $this->evaluate($model));
    }

    public function testNoFindingWhenDatastoreIsNotStrictlyConfidential(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('db');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore']; // no handles_strictly_confidential
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        self::assertSame([], $this->evaluate($model));
    }

    public function testCustomGuardTraitsFromConfig(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('custom-guard');
        $guard = new TechnicalAsset('custom-guard');
        $guard->traits = ['my_custom_guard'];
        $guard->communicatesTo('db');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($web)->addTechnicalAsset($guard)->addTechnicalAsset($db);

        self::assertSame([], $this->evaluate($model, ['guard_traits' => ['my_custom_guard']]));
    }

    public function testMaxHopsFromConfigLimitsSearch(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('app');
        $app = new TechnicalAsset('app');
        $app->communicatesTo('db');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($web)->addTechnicalAsset($app)->addTechnicalAsset($db);

        self::assertSame([], $this->evaluate($model, ['max_hops' => 1]));
    }
}
