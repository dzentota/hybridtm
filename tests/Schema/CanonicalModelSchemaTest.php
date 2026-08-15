<?php
declare(strict_types=1);
namespace HybridTM\Tests\Schema;

use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Positive and negative coverage of the canonical model schema.
 * Every rejection case here corresponds to a class of bad input the API
 * must not accept.
 */
final class CanonicalModelSchemaTest extends TestCase
{
    private const SCHEMA  = __DIR__ . '/../../schema/canonical-model.v1.json';
    private const EXAMPLE = __DIR__ . '/../../examples/canonical/ecommerce.model.json';

    protected function setUp(): void
    {
        if (!class_exists(Validator::class)) {
            self::markTestSkipped('opis/json-schema is not installed.');
        }
    }

    public function testExampleModelIsValid(): void
    {
        $result = $this->validator()->validate($this->example(), $this->schema());

        $errors = $result->error() === null ? [] : (new ErrorFormatter())->format($result->error());
        self::assertTrue($result->isValid(), 'Example model must validate: ' . json_encode($errors));
    }

    /** @return iterable<string, array{callable(object): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'identifier is not a slug' => [static function (object $d): void {
            $d->components[0]->id = 'Frontend_Proxy';
        }];
        yield 'unknown protocol' => [static function (object $d): void {
            $d->dataFlows[0]->protocol = 'quic';
        }];
        yield 'unknown business criticality' => [static function (object $d): void {
            $d->model->businessCriticality = 'extreme';
        }];
        yield 'undeclared property on component' => [static function (object $d): void {
            $d->components[0]->colour = 'green';
        }];
        yield 'accepted risk without expiry' => [static function (object $d): void {
            unset($d->riskTracking[0]->expiresAt);
        }];
        yield 'justification too short' => [static function (object $d): void {
            $d->riskTracking[0]->justification = 'ok';
        }];
        yield 'wrong schema version' => [static function (object $d): void {
            $d->schemaVersion = 2;
        }];
        yield 'components missing' => [static function (object $d): void {
            unset($d->components);
        }];
        yield 'malformed finding stable id' => [static function (object $d): void {
            $d->riskTracking[0]->findingStableId = 'zzz';
        }];
        yield 'trust boundary without type' => [static function (object $d): void {
            unset($d->trustBoundaries[0]->type);
        }];
    }

    /** @param callable(object): void $mutate */
    #[DataProvider('invalidMutations')]
    public function testInvalidModelsAreRejected(callable $mutate): void
    {
        $document = $this->example();
        $mutate($document);

        self::assertFalse(
            $this->validator()->validate($document, $this->schema())->isValid(),
            'Schema accepted a document it should have rejected.',
        );
    }

    private function validator(): Validator
    {
        return new Validator();
    }

    private function schema(): object
    {
        return json_decode((string) file_get_contents(self::SCHEMA), false, 512, JSON_THROW_ON_ERROR);
    }

    private function example(): object
    {
        return json_decode((string) file_get_contents(self::EXAMPLE), false, 512, JSON_THROW_ON_ERROR);
    }
}
