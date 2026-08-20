<?php

declare(strict_types=1);

namespace HybridTM\Tests\Schema\Kb;

use PHPUnit\Framework\Attributes\DataProvider;

final class TraitSchemaTest extends KbSchemaTestCase
{
    protected function schemaPath(): string
    {
        return __DIR__ . '/../../../schema/kb/trait.v1.json';
    }

    protected function examplePath(): string
    {
        return __DIR__ . '/../../../examples/kb/trait.example.json';
    }

    /** @return iterable<string, array{callable(\stdClass): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'wrong kind' => [static function (\stdClass $d): void {
            $d->kind = 'Component';
        }];
        yield 'wrong apiVersion' => [static function (\stdClass $d): void {
            $d->apiVersion = 'hybridtm.io/kb/v2';
        }];
        yield 'id is not snake_case' => [static function (\stdClass $d): void {
            $d->metadata->id = 'Not-Valid';
        }];
        yield 'missing derived flag' => [static function (\stdClass $d): void {
            unset($d->spec->derived);
        }];
        yield 'derived is not boolean' => [static function (\stdClass $d): void {
            $d->spec->derived = 'true';
        }];
        yield 'missing label' => [static function (\stdClass $d): void {
            unset($d->spec->label);
        }];
        yield 'undeclared spec property' => [static function (\stdClass $d): void {
            $d->spec->extra = 'nope';
        }];
    }

    #[DataProvider('invalidMutations')]
    public function testInvalidDocumentsAreRejected(callable $mutate): void
    {
        $this->assertRejected($mutate);
    }
}
