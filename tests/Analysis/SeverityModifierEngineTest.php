<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\Finding;
use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\SeverityModifierEngine;
use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Enums\Quantity;
use PHPUnit\Framework\TestCase;

final class SeverityModifierEngineTest extends TestCase
{
    private function finding(SubjectRef $subject, Likelihood $likelihood = Likelihood::Likely, Impact $impact = Impact::Medium): Finding
    {
        return Finding::create(
            threatId: 'THREAT-X',
            ruleId: 'rule/x',
            subject: $subject,
            title: 'X',
            likelihood: $likelihood,
            impact: $impact,
        );
    }

    private function engine(): SeverityModifierEngine
    {
        return new SeverityModifierEngine();
    }

    public function testInternetReachableAssetBumpsLikelihood(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web')); // caller pre-marks via DerivedTraits below

        $derived = new DerivedTraits();
        $derived->add('web', 'internet_reachable');
        $index = ModelIndex::build($model);

        $finding = $this->finding(SubjectRef::component('web'));
        $adjusted = $this->engine()->apply($finding, $model, $index, $derived);

        self::assertSame(Likelihood::VeryLikely, $adjusted->likelihood);
        self::assertSame($finding->stableId, $adjusted->stableId, 'stableId must be unaffected by rescoring');
    }

    public function testNotInternetReachableLeavesLikelihoodUnchanged(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $index = ModelIndex::build($model);

        $finding = $this->finding(SubjectRef::component('web'));
        $adjusted = $this->engine()->apply($finding, $model, $index, new DerivedTraits());

        self::assertSame(Likelihood::Likely, $adjusted->likelihood);
        self::assertSame($finding, $adjusted, 'no modifiers applicable -> same instance returned');
    }

    public function testAssetOutsideAllTrustBoundariesBumpsLikelihood(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('orphan'));
        $model->addTechnicalAsset(new TechnicalAsset('inside'));
        $boundary = new TrustBoundary('net');
        $boundary->addAssets('inside');
        $model->addTrustBoundary($boundary);
        $index = ModelIndex::build($model);

        $orphanFinding = $this->engine()->apply($this->finding(SubjectRef::component('orphan')), $model, $index, new DerivedTraits());
        $insideFinding = $this->engine()->apply($this->finding(SubjectRef::component('inside')), $model, $index, new DerivedTraits());

        self::assertSame(Likelihood::VeryLikely, $orphanFinding->likelihood);
        self::assertSame(Likelihood::Likely, $insideFinding->likelihood);
    }

    public function testBoundaryModifierSkippedWhenModelHasNoBoundariesAtAll(): void
    {
        // Same judgment call as AssetOutsideTrustBoundaryRule (§3.6): a model
        // that hasn't declared any boundary yet is unstarted, not exposed.
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::component('web')), $model, $index, new DerivedTraits());
        self::assertSame(Likelihood::Likely, $adjusted->likelihood);
    }

    public function testStrictlyConfidentialDataBumpsImpact(): void
    {
        $model = new ThreatModel('App');
        $secret = new DataAsset('secret');
        $secret->confidentiality = Confidentiality::StrictlyConfidential;
        $model->addDataAsset($secret);
        $asset = new TechnicalAsset('vault');
        $asset->dataAssetsStored = ['secret'];
        $model->addTechnicalAsset($asset);
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::component('vault')), $model, $index, new DerivedTraits());
        self::assertSame(Impact::High, $adjusted->impact);
    }

    public function testMissionCriticalBusinessCriticalityBumpsImpact(): void
    {
        $model = new ThreatModel('App');
        $model->businessCriticality = BusinessCriticality::MissionCritical;
        $model->addTechnicalAsset(new TechnicalAsset('svc'));
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::component('svc')), $model, $index, new DerivedTraits());
        self::assertSame(Impact::High, $adjusted->impact);
    }

    public function testMissionCriticalAppliesEvenToModelScopeFindings(): void
    {
        $model = new ThreatModel('App');
        $model->businessCriticality = BusinessCriticality::MissionCritical;
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::model()), $model, $index, new DerivedTraits());
        self::assertSame(Impact::High, $adjusted->impact);
    }

    public function testVeryManyQuantityBumpsImpact(): void
    {
        $model = new ThreatModel('App');
        $data = new DataAsset('bulk');
        $data->quantity = Quantity::VeryMany;
        $model->addDataAsset($data);
        $asset = new TechnicalAsset('svc');
        $asset->dataAssetsProcessed = ['bulk'];
        $model->addTechnicalAsset($asset);
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::component('svc')), $model, $index, new DerivedTraits());
        self::assertSame(Impact::High, $adjusted->impact);
    }

    public function testModifiersStackAndClampAtScaleEnds(): void
    {
        $model = new ThreatModel('App');
        $model->businessCriticality = BusinessCriticality::MissionCritical;
        $data = new DataAsset('secret');
        $data->confidentiality = Confidentiality::StrictlyConfidential;
        $data->quantity = Quantity::VeryMany;
        $model->addDataAsset($data);
        $asset = new TechnicalAsset('svc');
        $asset->dataAssetsStored = ['secret'];
        $model->addTechnicalAsset($asset);
        $index = ModelIndex::build($model);

        // impact starts at VeryHigh (top of scale) — 3 modifiers would want +3 but clamp at VeryHigh.
        $finding = $this->finding(SubjectRef::component('svc'), impact: Impact::VeryHigh);
        $adjusted = $this->engine()->apply($finding, $model, $index, new DerivedTraits());
        self::assertSame(Impact::VeryHigh, $adjusted->impact);
    }

    public function testFlowSubjectUsesDataSentAndReceived(): void
    {
        $model = new ThreatModel('App');
        $secret = new DataAsset('secret');
        $secret->confidentiality = Confidentiality::StrictlyConfidential;
        $model->addDataAsset($secret);
        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db');
        $link->dataSent = ['secret'];
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::flow('web', 'db')), $model, $index, new DerivedTraits());
        self::assertSame(Impact::High, $adjusted->impact);
    }

    public function testFlowSubjectChecksBothEndpointsForInternetReachability(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));
        $index = ModelIndex::build($model);

        $derived = new DerivedTraits();
        $derived->add('db', 'internet_reachable'); // target end is reachable, not the source

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::flow('web', 'db')), $model, $index, $derived);
        self::assertSame(Likelihood::VeryLikely, $adjusted->likelihood);
    }

    public function testCapableThreatActorBumpsLikelihood(): void
    {
        $model = new ThreatModel('App');
        $actor = new TechnicalAsset('attacker');
        $actor->traits = ['threat_actor'];
        $actor->properties->set('capability', 'apt');
        $model->addTechnicalAsset($actor);
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::component('attacker')), $model, $index, new DerivedTraits());
        self::assertSame(Likelihood::VeryLikely, $adjusted->likelihood);
    }

    public function testLowCapabilityThreatActorLeavesLikelihoodUnchanged(): void
    {
        $model = new ThreatModel('App');
        $actor = new TechnicalAsset('attacker');
        $actor->traits = ['threat_actor'];
        $actor->properties->set('capability', 'script_kiddie');
        $model->addTechnicalAsset($actor);
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::component('attacker')), $model, $index, new DerivedTraits());
        self::assertSame(Likelihood::Likely, $adjusted->likelihood);
    }

    public function testPrivilegedThreatActorBumpsImpact(): void
    {
        $model = new ThreatModel('App');
        $actor = new TechnicalAsset('insider');
        $actor->traits = ['threat_actor'];
        $actor->properties->set('privilege_level', 'admin');
        $model->addTechnicalAsset($actor);
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::component('insider')), $model, $index, new DerivedTraits());
        self::assertSame(Impact::High, $adjusted->impact);
    }

    public function testFlowFromPrivilegedActorBumpsImpactOnTargetSubject(): void
    {
        $model = new ThreatModel('App');
        $actor = new TechnicalAsset('insider');
        $actor->traits = ['threat_actor'];
        $actor->properties->set('privilege_level', 'system');
        $actor->communicatesTo('db');
        $model->addTechnicalAsset($actor)->addTechnicalAsset(new TechnicalAsset('db'));
        $index = ModelIndex::build($model);

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::flow('insider', 'db')), $model, $index, new DerivedTraits());
        self::assertSame(Impact::High, $adjusted->impact);
    }

    public function testBoundarySubjectChecksContainedAssets(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $boundary = new TrustBoundary('dmz');
        $boundary->addAssets('web');
        $model->addTrustBoundary($boundary);
        $index = ModelIndex::build($model);

        $derived = new DerivedTraits();
        $derived->add('web', 'internet_reachable');

        $adjusted = $this->engine()->apply($this->finding(SubjectRef::boundary('dmz')), $model, $index, $derived);
        self::assertSame(Likelihood::VeryLikely, $adjusted->likelihood);
    }
}
