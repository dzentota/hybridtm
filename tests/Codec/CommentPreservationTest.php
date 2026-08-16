<?php
declare(strict_types=1);
namespace HybridTM\Tests\Codec;

use HybridTM\Codec\PhpDslReader;
use HybridTM\Codec\PhpDslWriter;
use PHPUnit\Framework\TestCase;

/** T-4.5: a comment above an entity's construction line survives read/write cycles. */
final class CommentPreservationTest extends TestCase
{
    private PhpDslReader $reader;
    private PhpDslWriter $writer;

    protected function setUp(): void
    {
        $this->reader = new PhpDslReader();
        $this->writer = new PhpDslWriter();
    }

    public function testCapturesLineCommentAboveTechnicalAsset(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
// The main customer-facing web application
$web = new TechnicalAsset('web', 'web');
$model->addTechnicalAsset($web);
return $model;
PHP);

        self::assertTrue($result->isCanonical());
        self::assertSame(
            '// The main customer-facing web application',
            $result->comments['TechnicalAsset:web'],
        );
    }

    public function testCapturesDocCommentBlock(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
/**
 * Customer PII collected at signup.
 * Subject to GDPR Article 4.
 */
$pii = new DataAsset('customer-pii');
$model->addDataAsset($pii);
return $model;
PHP);

        self::assertTrue($result->isCanonical());
        self::assertStringContainsString('Customer PII collected at signup.', $result->comments['DataAsset:customer-pii']);
        self::assertStringContainsString('GDPR Article 4', $result->comments['DataAsset:customer-pii']);
    }

    public function testCapturesCommentAboveThreatModelItself(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\ThreatModel;
// Top-level threat model for the e-commerce platform.
$model = new ThreatModel('App');
return $model;
PHP);

        self::assertSame('// Top-level threat model for the e-commerce platform.', $result->comments['ThreatModel']);
    }

    public function testWriterEmitsCommentAboveTheEntity(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
// Important note
$web = new TechnicalAsset('web', 'web');
$model->addTechnicalAsset($web);
return $model;
PHP);

        $code = $this->writer->write($result->model, $result->comments);
        self::assertStringContainsString("// Important note\n\$", $code);

        // The comment line must precede the entity's construction line.
        $commentPos = strpos($code, '// Important note');
        $constructPos = strpos($code, "new TechnicalAsset('web', 'web')");
        self::assertLessThan($constructPos, $commentPos);
    }

    public function testCommentSurvivesTenReadWriteCycles(): void
    {
        $code = <<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
// Survives every cycle
$web = new TechnicalAsset('web', 'web');
$model->addTechnicalAsset($web);
return $model;
PHP;

        for ($i = 0; $i < 10; $i++) {
            $result = $this->reader->read($code);
            self::assertTrue($result->isCanonical(), "cycle {$i} must stay canonical");
            self::assertSame('// Survives every cycle', $result->comments['TechnicalAsset:web'], "cycle {$i} lost the comment");
            $code = $this->writer->write($result->model, $result->comments);
        }
    }

    public function testWithoutPassingCommentsBackTheyAreDropped(): void
    {
        // Documents the contract: comments are a side-channel the caller
        // must thread through explicitly, not an implicit property of the model.
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
// This will be lost if not passed to write()
$web = new TechnicalAsset('web', 'web');
$model->addTechnicalAsset($web);
return $model;
PHP);

        $code = $this->writer->write($result->model); // comments not passed
        self::assertStringNotContainsString('This will be lost', $code);
    }

    public function testEntitiesWithoutCommentsAreUnaffected(): void
    {
        $result = $this->reader->read(<<<'PHP'
<?php
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
$model = new ThreatModel('App');
$web = new TechnicalAsset('web', 'web');
$model->addTechnicalAsset($web);
return $model;
PHP);

        self::assertSame([], $result->comments);
        $code = $this->writer->write($result->model, $result->comments);
        self::assertStringContainsString("\$web = new TechnicalAsset('web', 'web');", $code);
    }
}
