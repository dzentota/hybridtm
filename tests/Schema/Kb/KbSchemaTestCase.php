<?php
declare(strict_types=1);
namespace HybridTM\Tests\Schema\Kb;

use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\TestCase;

/** Shared plumbing for the seven KB entity-kind schema tests (T-2.1). */
abstract class KbSchemaTestCase extends TestCase
{
    abstract protected function schemaPath(): string;

    abstract protected function examplePath(): string;

    protected function setUp(): void
    {
        if (!class_exists(Validator::class)) {
            self::markTestSkipped('opis/json-schema is not installed.');
        }
    }

    public function testExampleIsValid(): void
    {
        $result = $this->validator()->validate($this->example(), $this->schema());

        $errors = $result->error() === null ? [] : (new ErrorFormatter())->format($result->error());
        self::assertTrue($result->isValid(), 'Example document must validate: ' . json_encode($errors));
    }

    /** @param callable(object): void $mutate */
    protected function assertRejected(callable $mutate): void
    {
        $document = $this->example();
        $mutate($document);

        self::assertFalse(
            $this->validator()->validate($document, $this->schema())->isValid(),
            'Schema accepted a document it should have rejected.',
        );
    }

    protected function validator(): Validator
    {
        return new Validator();
    }

    protected function schema(): object
    {
        return json_decode((string) file_get_contents($this->schemaPath()), false, 512, JSON_THROW_ON_ERROR);
    }

    protected function example(): object
    {
        return json_decode((string) file_get_contents($this->examplePath()), false, 512, JSON_THROW_ON_ERROR);
    }
}
