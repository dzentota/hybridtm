<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\MitigationIndex;
use HybridTM\Analysis\StoryCoverageAnalyzer;
use HybridTM\Analysis\StoryCoverageStatus;
use HybridTM\Compiler\DiscoveredAbuserStoryRef;
use HybridTM\Compiler\DiscoveredMitigation;
use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\AbuseCaseStatus;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Kb\InMemoryKnowledgeBase;
use HybridTM\Kb\Kind;
use PHPUnit\Framework\TestCase;

final class StoryCoverageAnalyzerTest extends TestCase
{
    public function testCoveredWhenMitigationAndAbuserStoryShareContext(): void
    {
        $model = new ThreatModel('App');
        $actor = new TechnicalAsset('attacker');
        $actor->traits = ['threat_actor'];
        $model->addTechnicalAsset($actor);
        $web = new TechnicalAsset('web-app');
        $model->addTechnicalAsset($web);

        $case = new AbuseCase('brute-force-login', 'Guess passwords');
        $case->actorId = 'attacker';
        $case->assetIds = ['web-app'];
        $case->requiredCwes = ['CWE-307'];
        $model->addAbuseCase($case);

        $mitigations = MitigationIndex::fromDiscoveries([
            new DiscoveredMitigation(
                'CWE-307',
                'Account lockout',
                MitigationStatus::Mitigated,
                'App\\LoginController::authenticate',
                assetId: 'web-app',
                abuserStoryIds: ['brute-force-login'],
            ),
        ]);

        $coverage = (new StoryCoverageAnalyzer())->analyze(
            $model,
            new InMemoryKnowledgeBase([], 'empty'),
            $mitigations,
            [
                new DiscoveredAbuserStoryRef(
                    'brute-force-login',
                    'App\\LoginController::authenticate',
                    'web-app',
                    ['CWE-307'],
                ),
            ],
        );

        self::assertCount(1, $coverage);
        self::assertSame(StoryCoverageStatus::Covered, $coverage[0]->status);
        self::assertSame(['CWE-307'], $coverage[0]->coveredCwes);
        self::assertSame([], $coverage[0]->missingCwes);
    }

    public function testPartialAndAcceptedStatuses(): void
    {
        $model = new ThreatModel('App');
        $partial = new AbuseCase('partial-story');
        $partial->requiredCwes = ['CWE-307', 'CWE-521'];
        $model->addAbuseCase($partial);

        $accepted = new AbuseCase('accepted-story');
        $accepted->requiredCwes = ['CWE-89'];
        $accepted->status = AbuseCaseStatus::Accepted;
        $model->addAbuseCase($accepted);

        $mitigations = MitigationIndex::fromDiscoveries([
            new DiscoveredMitigation(
                'CWE-307',
                'lockout',
                MitigationStatus::Mitigated,
                'Ctx',
                assetId: 'web',
                abuserStoryIds: ['partial-story'],
            ),
        ]);

        $coverage = (new StoryCoverageAnalyzer())->analyze(
            $model,
            new InMemoryKnowledgeBase([], 'empty'),
            $mitigations,
        );

        $byId = [];
        foreach ($coverage as $c) {
            $byId[$c->storyId] = $c;
        }

        self::assertSame(StoryCoverageStatus::Partial, $byId['partial-story']->status);
        self::assertSame(['CWE-521'], $byId['partial-story']->missingCwes);
        self::assertSame(StoryCoverageStatus::Accepted, $byId['accepted-story']->status);
    }

    public function testDerivesCwesFromKbThreat(): void
    {
        $model = new ThreatModel('App');
        $case = new AbuseCase('from-threat');
        $case->threatIds = ['THREAT-X'];
        $model->addAbuseCase($case);

        $kb = new InMemoryKnowledgeBase([
            Kind::Threat->value => [
                'THREAT-X' => [
                    'id' => 'THREAT-X',
                    'title' => 'X',
                    'standards' => ['cwe' => [307]],
                ],
            ],
        ], 'test');

        $coverage = (new StoryCoverageAnalyzer())->analyze($model, $kb, null);
        self::assertSame(['CWE-307'], $coverage[0]->requiredCwes);
        self::assertSame(StoryCoverageStatus::Uncovered, $coverage[0]->status);
    }
}
