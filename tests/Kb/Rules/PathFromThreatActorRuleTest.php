<?php

declare(strict_types=1);

namespace HybridTM\Tests\Kb\Rules;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\Finding;
use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\Rules\RuleContext;
use HybridTM\Analysis\Rules\RuleContextGraph;
use HybridTM\Analysis\Rules\RuleContextModel;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Authentication;
use HybridTM\Kb\InMemoryKnowledgeBase;
use HybridTM\Kb\Kind;
use HybridTM\Kb\Rules\PathFromThreatActorRule;
use PHPUnit\Framework\TestCase;

final class PathFromThreatActorRuleTest extends TestCase
{
    private function kb(): InMemoryKnowledgeBase
    {
        return new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-ACTOR-REACHABLE-DATASTORE' => [
                    'title' => 'Actor-reachable datastore',
                    'summary' => 'summary',
                    'stride' => ['information-disclosure'],
                    'countermeasures' => [],
                    'metadata' => ['id' => 'THREAT-ACTOR-REACHABLE-DATASTORE'],
                ],
            ],
        ], 'test-kb');
    }

    /**
     * @param array<string, mixed> $config
     * @return list<Finding>
     */
    private function evaluate(ThreatModel $model, array $config = []): array
    {
        $index = ModelIndex::build($model);
        $derived = new DerivedTraits();
        $ctx = new RuleContext(
            'topology/path-from-threat-actor',
            new RuleContextModel($model, $derived),
            new RuleContextGraph($model, $index, $derived),
            $this->kb(),
            $config,
        );

        return iterator_to_array((new PathFromThreatActorRule())->evaluate($ctx), false);
    }

    private function actor(string $id, string $privilege): TechnicalAsset
    {
        $actor = new TechnicalAsset($id);
        $actor->traits = ['threat_actor'];
        $actor->properties->set('privilege_level', $privilege);
        return $actor;
    }

    public function testAnonymousActorReachesUnguardedDatastoreOverUnauthenticatedLink(): void
    {
        $model = new ThreatModel('App');
        $attacker = $this->actor('attacker', 'none');
        $attacker->communicatesTo('db', authentication: Authentication::None);
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($attacker)->addTechnicalAsset($db);

        $findings = $this->evaluate($model);

        self::assertCount(1, $findings);
        self::assertSame('THREAT-ACTOR-REACHABLE-DATASTORE', $findings[0]->threatId);
        self::assertStringContainsString('attacker', $findings[0]->evidence[0]);
    }

    public function testAnonymousActorBlockedByCredentialedLink(): void
    {
        $model = new ThreatModel('App');
        $attacker = $this->actor('attacker', 'none');
        $attacker->communicatesTo('db', authentication: Authentication::Credentials);
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($attacker)->addTechnicalAsset($db);

        self::assertSame([], $this->evaluate($model));
    }

    public function testAuthenticatedUserActorCrossesCredentialedLink(): void
    {
        $model = new ThreatModel('App');
        $actor = $this->actor('malicious-user', 'user');
        $actor->communicatesTo('db', authentication: Authentication::Credentials);
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($actor)->addTechnicalAsset($db);

        $findings = $this->evaluate($model);

        self::assertCount(1, $findings);
        self::assertStringContainsString('malicious-user', $findings[0]->evidence[0]);
    }

    public function testNoFindingWhenPathIsGuarded(): void
    {
        $model = new ThreatModel('App');
        $attacker = $this->actor('attacker', 'system');
        $attacker->communicatesTo('waf', authentication: Authentication::None);
        $waf = new TechnicalAsset('waf');
        $waf->traits = ['waf'];
        $waf->communicatesTo('db');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($attacker)->addTechnicalAsset($waf)->addTechnicalAsset($db);

        self::assertSame([], $this->evaluate($model));
    }

    public function testNoFindingWithoutAnyModeledThreatActor(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('db', authentication: Authentication::None);
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        self::assertSame([], $this->evaluate($model));
    }
}
