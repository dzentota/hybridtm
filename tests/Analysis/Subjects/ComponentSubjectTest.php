<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis\Subjects;

use HybridTM\Analysis\DerivedTraits;
use HybridTM\Analysis\Subjects\ComponentSubject;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\Encryption;
use PHPUnit\Framework\TestCase;

final class ComponentSubjectTest extends TestCase
{
    public function testExposesBasicFields(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('web', 'Web');
        $asset->encryption = Encryption::Transparent;
        $asset->internet = true;
        $model->addTechnicalAsset($asset);

        $subject = new ComponentSubject($asset, $model, new DerivedTraits());

        self::assertSame('web', $subject->id);
        self::assertSame('Web', $subject->name);
        self::assertSame('transparent', $subject->encryption);
        self::assertTrue($subject->internet);
    }

    public function testHasTraitChecksDeclaredAndDerived(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('db');
        $asset->traits = ['datastore'];
        $model->addTechnicalAsset($asset);

        $derived = new DerivedTraits();
        $derived->add('db', 'directly_exposed_datastore');

        $subject = new ComponentSubject($asset, $model, $derived);

        self::assertTrue($subject->hasTrait('datastore'));
        self::assertTrue($subject->hasTrait('directly_exposed_datastore'));
        self::assertTrue($subject->hasTrait('nonexistent', 'datastore'), 'OR semantics');
        self::assertFalse($subject->hasTrait('nonexistent'));
    }

    public function testHasAllTraitsAndSemantics(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('db');
        $asset->traits = ['datastore', 'sql_engine'];
        $model->addTechnicalAsset($asset);

        $subject = new ComponentSubject($asset, $model, new DerivedTraits());

        self::assertTrue($subject->hasAllTraits('datastore', 'sql_engine'));
        self::assertFalse($subject->hasAllTraits('datastore', 'nosql_engine'));
    }

    public function testStoresConfidentialityAtLeast(): void
    {
        $model = new ThreatModel('App');
        $secret = new DataAsset('secret');
        $secret->confidentiality = Confidentiality::StrictlyConfidential;
        $model->addDataAsset($secret);

        $asset = new TechnicalAsset('vault');
        $asset->dataAssetsStored = ['secret'];
        $model->addTechnicalAsset($asset);

        $subject = new ComponentSubject($asset, $model, new DerivedTraits());

        self::assertTrue($subject->storesConfidentialityAtLeast('confidential'));
        self::assertTrue($subject->storesConfidentialityAtLeast('strictly-confidential'));
    }

    public function testStoresConfidentialityAtLeastFalseWhenBelowThreshold(): void
    {
        $model = new ThreatModel('App');
        $model->addDataAsset(new DataAsset('metrics')); // default: internal
        $asset = new TechnicalAsset('svc');
        $asset->dataAssetsProcessed = ['metrics'];
        $model->addTechnicalAsset($asset);

        $subject = new ComponentSubject($asset, $model, new DerivedTraits());
        self::assertFalse($subject->storesConfidentialityAtLeast('confidential'));
    }

    public function testPropsExposesThePropertyBag(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('web');
        $asset->properties->set('internet_facing', true);
        $model->addTechnicalAsset($asset);

        $subject = new ComponentSubject($asset, $model, new DerivedTraits());
        self::assertTrue($subject->props->bool('internet_facing'));
    }

    public function testHasMitigationForIsAlwaysFalseInThisEngineVersion(): void
    {
        $model = new ThreatModel('App');
        $asset = new TechnicalAsset('svc');
        $model->addTechnicalAsset($asset);

        $subject = new ComponentSubject($asset, $model, new DerivedTraits());
        self::assertFalse($subject->hasMitigationFor('CWE-89'));
    }
}
