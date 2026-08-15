<?php
declare(strict_types=1);
namespace HybridTM\Tests\Schema\Kb;

use PHPUnit\Framework\Attributes\DataProvider;

final class RiskPatternSchemaTest extends KbSchemaTestCase
{
    protected function schemaPath(): string
    {
        return __DIR__ . '/../../../schema/kb/risk-pattern.v1.json';
    }

    protected function examplePath(): string
    {
        return __DIR__ . '/../../../examples/kb/risk-pattern.example.json';
    }

    /** @return iterable<string, array{callable(object): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'id does not start with RP-' => [static function (object $d): void { $d->metadata->id = 'INTERNET-FACING-PROXY'; }];
        yield 'missing applies_when' => [static function (object $d): void { unset($d->spec->applies_when); }];
        yield 'empty threats list' => [static function (object $d): void { $d->spec->threats = []; }];
        yield 'threat id malformed' => [static function (object $d): void { $d->spec->threats[] = 'ddos'; }];
        yield 'missing version' => [static function (object $d): void { unset($d->metadata->version); }];
        yield 'undeclared spec property' => [static function (object $d): void { $d->spec->extra = 'nope'; }];
    }

    #[DataProvider('invalidMutations')]
    public function testInvalidDocumentsAreRejected(callable $mutate): void
    {
        $this->assertRejected($mutate);
    }
}
