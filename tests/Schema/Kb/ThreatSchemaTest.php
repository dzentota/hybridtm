<?php

declare(strict_types=1);

namespace HybridTM\Tests\Schema\Kb;

use PHPUnit\Framework\Attributes\DataProvider;

final class ThreatSchemaTest extends KbSchemaTestCase
{
    protected function schemaPath(): string
    {
        return __DIR__ . '/../../../schema/kb/threat.v1.json';
    }

    protected function examplePath(): string
    {
        return __DIR__ . '/../../../examples/kb/threat.example.json';
    }

    /** @return iterable<string, array{callable(\stdClass): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'id does not start with THREAT-' => [static function (\stdClass $d): void {
            $d->metadata->id = 'DATA-AT-REST';
        }];
        yield 'unknown stride value' => [static function (\stdClass $d): void {
            $d->spec->stride = ['sql-injection'];
        }];
        yield 'empty stride list' => [static function (\stdClass $d): void {
            $d->spec->stride = [];
        }];
        yield 'unknown likelihood' => [static function (\stdClass $d): void {
            $d->spec->base->likelihood = 'certain';
        }];
        yield 'missing base.impact' => [static function (\stdClass $d): void {
            unset($d->spec->base->impact);
        }];
        yield 'countermeasure id malformed' => [static function (\stdClass $d): void {
            $d->spec->countermeasures = ['encrypt-at-rest'];
        }];
        yield 'reference missing url' => [static function (\stdClass $d): void {
            unset($d->spec->references[0]->url);
        }];
        yield 'missing summary' => [static function (\stdClass $d): void {
            unset($d->spec->summary);
        }];
    }

    #[DataProvider('invalidMutations')]
    public function testInvalidDocumentsAreRejected(callable $mutate): void
    {
        $this->assertRejected($mutate);
    }
}
