<?php
declare(strict_types=1);
namespace HybridTM\Tests\Analysis\Subjects;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\Subjects\FlowSubject;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\Protocol;
use PHPUnit\Framework\TestCase;

final class FlowSubjectTest extends TestCase
{
    private function buildSubject(ThreatModel $model, string $sourceId, string $linkId): FlowSubject
    {
        $index = ModelIndex::build($model);
        $link = $model->getTechnicalAsset($sourceId)->communicationLinks[$linkId];
        return new FlowSubject($link, $sourceId, $model, $index, new DerivedTraits());
    }

    public function testExposesBasicFields(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db', Protocol::Https);
        $link->vpn = true;
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $subject = $this->buildSubject($model, 'web', 'web-to-db');

        self::assertSame('web', $subject->sourceId);
        self::assertSame('db', $subject->targetId);
        self::assertTrue($subject->vpn);
        self::assertSame('https', $subject->protocol->value);
        self::assertTrue($subject->protocol->isEncrypted());
    }

    public function testSourceAndTargetAreComponentSubjects(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web', 'Web App');
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db', 'Database'));

        $subject = $this->buildSubject($model, 'web', 'web-to-db');

        self::assertSame('Web App', $subject->source->name);
        self::assertSame('Database', $subject->target->name);
    }

    public function testCrossesTrustBoundaryWhenAssetsInDifferentBoundaries(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));
        $dmz = new TrustBoundary('dmz');
        $dmz->addAssets('web');
        $private = new TrustBoundary('private');
        $private->addAssets('db');
        $model->addTrustBoundary($dmz)->addTrustBoundary($private);

        self::assertTrue($this->buildSubject($model, 'web', 'web-to-db')->crossesTrustBoundary());
    }

    public function testDoesNotCrossTrustBoundaryWhenAssetsShareOne(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->communicatesTo('db');
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));
        $net = new TrustBoundary('net');
        $net->addAssets('web', 'db');
        $model->addTrustBoundary($net);

        self::assertFalse($this->buildSubject($model, 'web', 'web-to-db')->crossesTrustBoundary());
    }

    public function testCarriesDataAtLeast(): void
    {
        $model = new ThreatModel('App');
        $secret = new DataAsset('secret');
        $secret->confidentiality = Confidentiality::StrictlyConfidential;
        $model->addDataAsset($secret);

        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db');
        $link->dataSent = ['secret'];
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        $subject = $this->buildSubject($model, 'web', 'web-to-db');
        self::assertTrue($subject->carriesDataAtLeast('confidential'));
        self::assertTrue($subject->carriesDataAtLeast('strictly-confidential'));
    }

    public function testCarriesDataAtLeastFalseBelowThreshold(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('metrics')); // default: internal

        $web = new TechnicalAsset('web');
        $link = $web->communicatesTo('db');
        $link->dataSent = ['metrics'];
        $model->addTechnicalAsset($web)->addTechnicalAsset(new TechnicalAsset('db'));

        self::assertFalse($this->buildSubject($model, 'web', 'web-to-db')->carriesDataAtLeast('confidential'));
    }
}
