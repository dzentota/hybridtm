<?php
declare(strict_types=1);
namespace HybridTM\Tests\Codec;

use HybridTM\Codec\ModelMerger;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use PHPUnit\Framework\TestCase;

final class ModelMergerTest extends TestCase
{
    private ModelMerger $merger;

    protected function setUp(): void
    {
        $this->merger = new ModelMerger();
    }

    private function baseModel(): ThreatModel
    {
        $model = new ThreatModel('App');
        $model->description = 'original';
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        return $model;
    }

    // ── clean, non-conflicting merges ───────────────────────────────────────

    public function testNonOverlappingAdditionsBothSurvive(): void
    {
        $base = $this->baseModel();

        $ours = $this->baseModel();
        $ours->addTechnicalAsset(new TechnicalAsset('cache'));

        $theirs = $this->baseModel();
        $theirs->addTechnicalAsset(new TechnicalAsset('queue'));

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertFalse($result->hasConflicts());
        self::assertNotNull($result->model->getTechnicalAsset('web'));
        self::assertNotNull($result->model->getTechnicalAsset('cache'));
        self::assertNotNull($result->model->getTechnicalAsset('queue'));
    }

    public function testOnlyOneSideChangingAScalarFieldWins(): void
    {
        $base = $this->baseModel();

        $ours = $this->baseModel();
        $ours->description = 'changed by ours';

        $theirs = $this->baseModel(); // unchanged

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertFalse($result->hasConflicts());
        self::assertSame('changed by ours', $result->model->description);
    }

    public function testOnlyTheirSideChangingAScalarFieldWins(): void
    {
        $base = $this->baseModel();
        $ours = $this->baseModel(); // unchanged

        $theirs = $this->baseModel();
        $theirs->description = 'changed by theirs';

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertFalse($result->hasConflicts());
        self::assertSame('changed by theirs', $result->model->description);
    }

    public function testIdenticalChangeOnBothSidesIsNotAConflict(): void
    {
        $base = $this->baseModel();

        $ours = $this->baseModel();
        $ours->businessCriticality = BusinessCriticality::Critical;

        $theirs = $this->baseModel();
        $theirs->businessCriticality = BusinessCriticality::Critical;

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertFalse($result->hasConflicts());
        self::assertSame(BusinessCriticality::Critical, $result->model->businessCriticality);
    }

    public function testCleanDeletionByOneSideRemovesEntity(): void
    {
        $base = $this->baseModel();
        $base->addTechnicalAsset(new TechnicalAsset('legacy'));

        $ours = $this->baseModel(); // 'legacy' deleted, 'web' untouched
        $theirs = $this->baseModel();
        $theirs->addTechnicalAsset(new TechnicalAsset('legacy')); // untouched, same as base

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertFalse($result->hasConflicts());
        self::assertNull($result->model->getTechnicalAsset('legacy'));
    }

    public function testIdenticallyAddedEntityOnBothSidesMergesCleanly(): void
    {
        $base = $this->baseModel();

        $ours = $this->baseModel();
        $ours->addDataAsset(new DataAsset('pii'));

        $theirs = $this->baseModel();
        $theirs->addDataAsset(new DataAsset('pii'));

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertFalse($result->hasConflicts());
        self::assertNotNull($result->model->getDataAsset('pii'));
    }

    // ── conflicts ────────────────────────────────────────────────────────────

    public function testBothSidesChangingTheSameFieldDifferentlyIsAConflict(): void
    {
        $base = $this->baseModel();

        $ours = $this->baseModel();
        $ours->description = 'ours version';

        $theirs = $this->baseModel();
        $theirs->description = 'theirs version';

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertTrue($result->hasConflicts());
        self::assertSame('ours version', $result->model->description, 'ours wins in the returned model');
        self::assertSame('model.description', $result->conflicts[0]->path);
        self::assertSame('original', $result->conflicts[0]->base);
        self::assertSame('ours version', $result->conflicts[0]->ours);
        self::assertSame('theirs version', $result->conflicts[0]->theirs);
    }

    public function testDifferentEntitiesAddedWithSameIdIsAConflict(): void
    {
        $base = $this->baseModel();

        $ours = $this->baseModel();
        $pii = new DataAsset('pii');
        $pii->confidentiality = Confidentiality::Confidential;
        $ours->addDataAsset($pii);

        $theirs = $this->baseModel();
        $piiOther = new DataAsset('pii');
        $piiOther->confidentiality = Confidentiality::StrictlyConfidential;
        $theirs->addDataAsset($piiOther);

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertTrue($result->hasConflicts());
        self::assertSame(Confidentiality::Confidential, $result->model->getDataAsset('pii')->confidentiality, 'ours wins');
    }

    public function testModifyVersusDeleteConflictKeepsTheModification(): void
    {
        $base = $this->baseModel();
        $base->addTechnicalAsset(new TechnicalAsset('legacy'));

        $ours = $this->baseModel(); // deletes 'legacy'

        $theirs = $this->baseModel();
        $legacy = new TechnicalAsset('legacy');
        $legacy->internet = true; // theirs modifies it
        $theirs->addTechnicalAsset($legacy);

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertTrue($result->hasConflicts());
        self::assertNotNull($result->model->getTechnicalAsset('legacy'), 'the modification must not be silently lost');
        self::assertTrue($result->model->getTechnicalAsset('legacy')->internet);
    }

    public function testDeleteVersusModifyConflictSymmetricCase(): void
    {
        $base = $this->baseModel();
        $base->addTechnicalAsset(new TechnicalAsset('legacy'));

        $ours = $this->baseModel();
        $legacy = new TechnicalAsset('legacy');
        $legacy->internet = true; // ours modifies it
        $ours->addTechnicalAsset($legacy);

        $theirs = $this->baseModel(); // deletes 'legacy'

        $result = $this->merger->merge3($base, $ours, $theirs);

        self::assertTrue($result->hasConflicts());
        self::assertNotNull($result->model->getTechnicalAsset('legacy'));
    }

    public function testNoConflictsWhenAllThreeAreIdentical(): void
    {
        $base = $this->baseModel();
        $result = $this->merger->merge3($base, $this->baseModel(), $this->baseModel());

        self::assertFalse($result->hasConflicts());
        self::assertSame('App', $result->model->title);
        self::assertSame('original', $result->model->description);
    }
}
