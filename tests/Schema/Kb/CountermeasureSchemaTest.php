<?php
declare(strict_types=1);
namespace HybridTM\Tests\Schema\Kb;

use PHPUnit\Framework\Attributes\DataProvider;

final class CountermeasureSchemaTest extends KbSchemaTestCase
{
    protected function schemaPath(): string
    {
        return __DIR__ . '/../../../schema/kb/countermeasure.v1.json';
    }

    protected function examplePath(): string
    {
        return __DIR__ . '/../../../examples/kb/countermeasure.example.json';
    }

    /** @return iterable<string, array{callable(object): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'id does not start with CM-' => [static function (object $d): void { $d->metadata->id = 'ENCRYPT-AT-REST'; }];
        yield 'unknown cost' => [static function (object $d): void { $d->spec->cost = 'expensive'; }];
        yield 'unknown category' => [static function (object $d): void { $d->spec->category = 'reactive'; }];
        yield 'implementation hint is not a string' => [static function (object $d): void {
            $d->spec->implementation->postgresql = ['not', 'a', 'string'];
        }];
        yield 'automated verification missing kind' => [static function (object $d): void {
            unset($d->spec->verification->automated[0]->kind);
        }];
        yield 'applies_property missing value' => [static function (object $d): void {
            unset($d->spec->applies_property->value);
        }];
        yield 'missing effectiveness' => [static function (object $d): void { unset($d->spec->effectiveness); }];
    }

    #[DataProvider('invalidMutations')]
    public function testInvalidDocumentsAreRejected(callable $mutate): void
    {
        $this->assertRejected($mutate);
    }
}
