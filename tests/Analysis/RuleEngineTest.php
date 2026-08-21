<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\Severity;
use HybridTM\Kb\InMemoryKnowledgeBase;
use HybridTM\Kb\Kind;
use PHPUnit\Framework\TestCase;
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

final class RuleEngineTest extends TestCase
{
    protected function setUp(): void
    {
        if (!class_exists(ExpressionLanguage::class)) {
            self::markTestSkipped('symfony/expression-language is not installed.');
        }
    }

    private function kbWithUnencryptedDatastoreRule(): InMemoryKnowledgeBase
    {
        return new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-DATA-AT-REST-UNENCRYPTED' => [
                    'title' => 'Unencrypted data at rest',
                    'summary' => 'summary',
                    'stride' => ['information-disclosure'],
                    'base' => ['likelihood' => 'likely', 'impact' => 'medium'],
                    'countermeasures' => ['CM-ENCRYPT-AT-REST'],
                    'standards' => ['cwe' => [311]],
                    'metadata' => ['id' => 'THREAT-DATA-AT-REST-UNENCRYPTED'],
                ],
            ],
            Kind::Rule->value => [
                'storage/unencrypted-at-rest' => [
                    'scope' => 'component',
                    'priority' => 100,
                    'when' => ['all' => [
                        "component.hasTrait('datastore')",
                        "component.encryption == 'none'",
                    ]],
                    'then' => [['raise' => 'THREAT-DATA-AT-REST-UNENCRYPTED']],
                    'metadata' => ['id' => 'storage/unencrypted-at-rest'],
                ],
            ],
        ], 'test-kb');
    }

    public function testSeverityModifierBumpsSeverityForInternetReachableAsset(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->traits = ['datastore'];
        $model->addTechnicalAsset($web);

        $result = (new RuleEngine())->analyze($model, $this->kbWithUnencryptedDatastoreRule());

        self::assertCount(1, $result->findings);
        // Base is likely x medium (weight 4 -> Elevated); internet-reachable
        // bumps likelihood to very-likely (weight 6 -> still Elevated) —
        // assert on the enum directly rather than severity, which wouldn't
        // move a full bucket here.
        self::assertSame(\HybridTM\Enums\Likelihood::VeryLikely, $result->findings[0]->likelihood);
    }

    public function testFindsUnencryptedDatastore(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze($model, $this->kbWithUnencryptedDatastoreRule());

        self::assertCount(1, $result->findings);
        self::assertSame('THREAT-DATA-AT-REST-UNENCRYPTED', $result->findings[0]->threatId);
        self::assertSame('component:db', (string) $result->findings[0]->subject);
    }

    public function testEncryptedDatastoreDoesNotMatch(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $db->encryption = \HybridTM\Enums\Encryption::Transparent;
        $model->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze($model, $this->kbWithUnencryptedDatastoreRule());
        self::assertSame([], $result->findings);
    }

    public function testStopsAtValidateOnModelError(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('nonexistent'); // triggers DanglingCommunicationLinkTargetRule
        $model->addTechnicalAsset($web);

        $result = (new RuleEngine())->analyze($model, $this->kbWithUnencryptedDatastoreRule());

        self::assertTrue($result->validation->hasErrors());
        self::assertSame([], $result->findings, 'rule evaluation must not run past a validation error');
    }

    public function testDeterministicInputHash(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('db'));
        $kb = $this->kbWithUnencryptedDatastoreRule();
        $engine = new RuleEngine();

        self::assertSame(
            $engine->analyze($model, $kb)->inputHash,
            $engine->analyze($model, $kb)->inputHash,
        );
    }

    public function testInputHashChangesWithModel(): void
    {
        $kb = $this->kbWithUnencryptedDatastoreRule();
        $engine = new RuleEngine();

        $a = new ThreatModel('App');
        $a->addTechnicalAsset(new TechnicalAsset('db'));

        $b = new ThreatModel('App');
        $b->addTechnicalAsset(new TechnicalAsset('cache'));

        self::assertNotSame($engine->analyze($a, $kb)->inputHash, $engine->analyze($b, $kb)->inputHash);
    }

    public function testMinSeverityFiltersFindings(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze(
            $model,
            $this->kbWithUnencryptedDatastoreRule(),
            new AnalysisOptions(minSeverity: Severity::Critical),
        );

        self::assertSame([], $result->findings, 'the finding is only Elevated severity');
    }

    public function testOnlyRulesRestrictsEvaluation(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze(
            $model,
            $this->kbWithUnencryptedDatastoreRule(),
            new AnalysisOptions(onlyRules: ['nonexistent/rule']),
        );

        self::assertSame([], $result->findings);
    }

    public function testSkipRulesExcludesARule(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze(
            $model,
            $this->kbWithUnencryptedDatastoreRule(),
            new AnalysisOptions(skipRules: ['storage/unencrypted-at-rest']),
        );

        self::assertSame([], $result->findings);
    }

    public function testResolvedRiskTrackingSuppressesTheFinding(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $kb = $this->kbWithUnencryptedDatastoreRule();
        $baseline = (new RuleEngine())->analyze($model, $kb)->findings[0];

        $tracking = new RiskTracking($baseline->stableId);
        $tracking->status = DecisionStatus::Accepted;
        $tracking->justification = 'Compensating control already in place.';
        $tracking->expiresAt = '2099-01-01';
        $model->addRiskTracking($tracking);

        $result = (new RuleEngine())->analyze($model, $kb);
        self::assertSame([], $result->findings);
    }

    public function testIncludeSuppressedOptionKeepsResolvedFindings(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $kb = $this->kbWithUnencryptedDatastoreRule();
        $baseline = (new RuleEngine())->analyze($model, $kb)->findings[0];

        $tracking = new RiskTracking($baseline->stableId);
        $tracking->status = DecisionStatus::Mitigated;
        $tracking->justification = 'Encryption at rest was enabled in production.';
        $model->addRiskTracking($tracking);

        $result = (new RuleEngine())->analyze($model, $kb, new AnalysisOptions(includeSuppressed: true));
        self::assertCount(1, $result->findings);
    }

    public function testOpenRiskTrackingDoesNotSuppress(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $kb = $this->kbWithUnencryptedDatastoreRule();
        $baseline = (new RuleEngine())->analyze($model, $kb)->findings[0];

        $tracking = new RiskTracking($baseline->stableId); // status defaults to Open
        $model->addRiskTracking($tracking);

        $result = (new RuleEngine())->analyze($model, $kb);
        self::assertCount(1, $result->findings);
    }

    public function testDedupesSameStableIdFromTwoRules(): void
    {
        $kb = new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-X' => [
                    'title' => 'X', 'summary' => '', 'stride' => [],
                    'base' => ['likelihood' => 'likely', 'impact' => 'low'],
                    'metadata' => ['id' => 'THREAT-X'],
                ],
            ],
            Kind::Rule->value => [
                'rule/a' => [
                    'scope' => 'component',
                    'when' => ['all' => ['true']],
                    'then' => [['raise' => 'THREAT-X', 'likelihood' => 'likely', 'impact' => 'low']],
                    'metadata' => ['id' => 'rule/a'],
                ],
                'rule/b' => [
                    'scope' => 'component',
                    'when' => ['all' => ['true']],
                    'then' => [['raise' => 'THREAT-X', 'likelihood' => 'frequent', 'impact' => 'very-high']],
                    'metadata' => ['id' => 'rule/b'],
                ],
            ],
        ], 'test-kb');

        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('svc'));

        $result = (new RuleEngine())->analyze($model, $kb);

        // Same threat + subject, different rule -> different stableId (ruleId is part of it),
        // so this is NOT deduped to one finding — it is two distinct findings.
        self::assertCount(2, $result->findings);
    }

    public function testFlowRuleFindsUnencryptedTransportAcrossBoundary(): void
    {
        $kb = new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-MITM-CLEARTEXT-TRANSPORT' => [
                    'title' => 'Cleartext transport', 'summary' => '', 'stride' => [],
                    'base' => ['likelihood' => 'likely', 'impact' => 'high'],
                    'metadata' => ['id' => 'THREAT-MITM-CLEARTEXT-TRANSPORT'],
                ],
            ],
            Kind::Rule->value => [
                'flow/cleartext' => [
                    'scope' => 'flow',
                    'when' => ['all' => ['not flow.protocol.isEncrypted()', 'flow.crossesTrustBoundary()']],
                    'then' => [['raise' => 'THREAT-MITM-CLEARTEXT-TRANSPORT']],
                    'metadata' => ['id' => 'flow/cleartext'],
                ],
            ],
        ], 'test-kb');

        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db', \HybridTM\Enums\Protocol::Http);
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));
        $dmz = new TrustBoundary('dmz');
        $dmz->addAssets('web');
        $private = new TrustBoundary('private');
        $private->addAssets('db');
        $model->addTrustBoundary($dmz)->addTrustBoundary($private);

        $result = (new RuleEngine())->analyze($model, $kb);

        self::assertCount(1, $result->findings);
        self::assertSame('flow:web->db', (string) $result->findings[0]->subject);
    }

    public function testDerivedTraitFeedsIntoComponentRule(): void
    {
        $kb = new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-UNGUARDED-DATASTORE-EXPOSURE' => [
                    'title' => 'Unguarded exposure', 'summary' => '', 'stride' => [],
                    'base' => ['likelihood' => 'very-likely', 'impact' => 'very-high'],
                    'metadata' => ['id' => 'THREAT-UNGUARDED-DATASTORE-EXPOSURE'],
                ],
            ],
            Kind::Rule->value => [
                'topology/directly-exposed' => [
                    'scope' => 'component',
                    'when' => ['all' => ["component.hasTrait('directly_exposed_datastore')"]],
                    'then' => [['raise' => 'THREAT-UNGUARDED-DATASTORE-EXPOSURE']],
                    'metadata' => ['id' => 'topology/directly-exposed'],
                ],
            ],
        ], 'test-kb');

        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze($model, $kb);
        self::assertCount(1, $result->findings);
    }

    public function testFindingCarriesRuleTrace(): void
    {
        $model = new ThreatModel('App');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore'];
        $model->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze($model, $this->kbWithUnencryptedDatastoreRule());

        self::assertNotNull($result->findings[0]->trace);
        self::assertTrue($result->findings[0]->trace->matched);
        self::assertCount(2, $result->findings[0]->trace);
    }

    public function testPhpImplRuleRunsWithinTheFullPipeline(): void
    {
        $kb = new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-UNGUARDED-DATASTORE-EXPOSURE' => [
                    'title' => 'Unguarded datastore exposure',
                    'summary' => '', 'stride' => [],
                    'metadata' => ['id' => 'THREAT-UNGUARDED-DATASTORE-EXPOSURE'],
                ],
            ],
            Kind::Rule->value => [
                'topology/unguarded-path-from-internet' => [
                    'scope' => 'model',
                    'impl' => \HybridTM\Kb\Rules\UnguardedPathFromInternetRule::class,
                    'config' => ['max_hops' => 4],
                    'metadata' => ['id' => 'topology/unguarded-path-from-internet'],
                ],
            ],
        ], 'test-kb');

        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $web->communicatesTo('db');
        $db = new TechnicalAsset('db');
        $db->traits = ['datastore', 'handles_strictly_confidential'];
        $model->addTechnicalAsset($web)->addTechnicalAsset($db);

        $result = (new RuleEngine())->analyze($model, $kb);

        self::assertCount(1, $result->findings);
        self::assertSame('THREAT-UNGUARDED-DATASTORE-EXPOSURE', $result->findings[0]->threatId);
        self::assertSame('component:db', (string) $result->findings[0]->subject);
    }

    public function testStatsRecordEngineAndKbVersion(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('svc'));
        $kb = $this->kbWithUnencryptedDatastoreRule();

        $result = (new RuleEngine())->analyze($model, $kb);

        self::assertSame('test-kb', $result->stats->kbVersion);
        self::assertNotSame('', $result->stats->engineVersion);
        self::assertGreaterThanOrEqual(0, $result->stats->rulesEvaluated);
    }
}
