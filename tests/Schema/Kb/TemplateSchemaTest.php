<?php
declare(strict_types=1);
namespace HybridTM\Tests\Schema\Kb;

use PHPUnit\Framework\Attributes\DataProvider;

final class TemplateSchemaTest extends KbSchemaTestCase
{
    protected function schemaPath(): string
    {
        return __DIR__ . '/../../../schema/kb/template.v1.json';
    }

    protected function examplePath(): string
    {
        return __DIR__ . '/../../../examples/kb/template.example.json';
    }

    /** @return iterable<string, array{callable(object): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'wrong kind' => [static function (object $d): void { $d->kind = 'Component'; }];
        yield 'missing components' => [static function (object $d): void { unset($d->spec->graph->components); }];
        yield 'empty components list' => [static function (object $d): void { $d->spec->graph->components = []; }];
        yield 'component missing type' => [static function (object $d): void {
            unset($d->spec->graph->components[0]->type);
        }];
        yield 'boundary missing contains' => [static function (object $d): void {
            unset($d->spec->graph->boundaries[0]->contains);
        }];
        yield 'flow missing protocol' => [static function (object $d): void {
            unset($d->spec->graph->flows[0]->protocol);
        }];
        yield 'missing description' => [static function (object $d): void { unset($d->spec->description); }];
    }

    #[DataProvider('invalidMutations')]
    public function testInvalidDocumentsAreRejected(callable $mutate): void
    {
        $this->assertRejected($mutate);
    }
}
