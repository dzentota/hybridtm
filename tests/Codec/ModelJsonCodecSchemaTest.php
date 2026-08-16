<?php
declare(strict_types=1);
namespace HybridTM\Tests\Codec;

use HybridTM\Codec\ModelJsonCodec;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Confidentiality;
use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\TestCase;

/** Confirms ModelJsonCodec::encode() output actually satisfies the schema it claims to implement. */
final class ModelJsonCodecSchemaTest extends TestCase
{
    private const SCHEMA = __DIR__ . '/../../schema/canonical-model.v1.json';

    protected function setUp(): void
    {
        if (!class_exists(Validator::class)) {
            self::markTestSkipped('opis/json-schema is not installed.');
        }
    }

    private function schema(): object
    {
        return json_decode((string) file_get_contents(self::SCHEMA), false, 512, JSON_THROW_ON_ERROR);
    }

    private function assertValidAgainstSchema(array $encoded): void
    {
        // Round-trip through JSON so arrays become the objects/lists opis expects.
        $document = json_decode((string) json_encode($encoded, JSON_THROW_ON_ERROR), false, 512, JSON_THROW_ON_ERROR);
        $result = (new Validator())->validate($document, $this->schema());

        $errors = $result->error() === null ? [] : (new ErrorFormatter())->format($result->error());
        self::assertTrue($result->isValid(), 'Encoded model must validate: ' . json_encode($errors));
    }

    public function testMinimalModelValidatesAgainstSchema(): void
    {
        $this->assertValidAgainstSchema((new ModelJsonCodec())->encode(new ThreatModel('App')));
    }

    public function testRichModelValidatesAgainstSchema(): void
    {
        $model = new ThreatModel('My App');
        $model->description = 'desc';
        $model->author = 'Alice';
        $model->date = '2026-01-01';

        $model->addDataAsset(new DataAsset('customer-pii', 'Customer PII'));

        $web = new TechnicalAsset('web', 'Web');
        $web->internet = true;
        $web->traits = ['datastore'];
        $web->tags = ['kb-component:web-server-nginx@1.0.0', 'edge'];
        $web->dataAssetsProcessed = ['customer-pii'];
        $link = $web->communicatesTo('db');
        $link->dataSent = ['customer-pii'];
        $model->addTechnicalAsset($web);

        $db = new TechnicalAsset('db', 'Database');
        $db->dataAssetsStored = ['customer-pii'];
        $model->addTechnicalAsset($db);

        $boundary = new TrustBoundary('dmz', 'DMZ');
        $boundary->addAssets('web');
        $model->addTrustBoundary($boundary);

        $this->assertValidAgainstSchema((new ModelJsonCodec())->encode($model, 'kb-core@1.0.0'));
    }

    public function testExampleThreatModelValidatesAgainstSchema(): void
    {
        $model = require __DIR__ . '/../../example/threat-model.php';
        $this->assertValidAgainstSchema((new ModelJsonCodec())->encode($model));
    }
}
