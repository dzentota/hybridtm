<?php
declare(strict_types=1);
namespace HybridTM\Tests\Schema\Kb;

use PHPUnit\Framework\Attributes\DataProvider;

final class ComponentSchemaTest extends KbSchemaTestCase
{
    protected function schemaPath(): string
    {
        return __DIR__ . '/../../../schema/kb/component.v1.json';
    }

    protected function examplePath(): string
    {
        return __DIR__ . '/../../../examples/kb/component.example.json';
    }

    /** @return iterable<string, array{callable(object): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'wrong kind' => [static function (object $d): void { $d->kind = 'Threat'; }];
        yield 'id is not a slug' => [static function (object $d): void { $d->metadata->id = 'Web_Server_Nginx'; }];
        yield 'version is not semver' => [static function (object $d): void { $d->metadata->version = 'v1'; }];
        yield 'unknown maturity' => [static function (object $d): void { $d->metadata->maturity = 'experimental'; }];
        yield 'missing mapping.type' => [static function (object $d): void { unset($d->spec->mapping->type); }];
        yield 'unknown mapping.type' => [static function (object $d): void { $d->spec->mapping->type = 'server'; }];
        yield 'port missing cardinality' => [static function (object $d): void {
            unset($d->spec->ports->inbound[0]->cardinality);
        }];
        yield 'property missing type' => [static function (object $d): void {
            unset($d->spec->properties[0]->type);
        }];
        yield 'undeclared top-level property' => [static function (object $d): void { $d->extraTopLevel = true; }];
        yield 'color is not a hex code' => [static function (object $d): void { $d->metadata->color = 'green'; }];
    }

    #[DataProvider('invalidMutations')]
    public function testInvalidDocumentsAreRejected(callable $mutate): void
    {
        $this->assertRejected($mutate);
    }
}
