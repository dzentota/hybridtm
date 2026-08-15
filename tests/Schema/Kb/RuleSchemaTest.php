<?php
declare(strict_types=1);
namespace HybridTM\Tests\Schema\Kb;

use Opis\JsonSchema\Validator;
use PHPUnit\Framework\Attributes\DataProvider;

final class RuleSchemaTest extends KbSchemaTestCase
{
    protected function schemaPath(): string
    {
        return __DIR__ . '/../../../schema/kb/rule.v1.json';
    }

    protected function examplePath(): string
    {
        return __DIR__ . '/../../../examples/kb/rule.example.json';
    }

    public function testImplVariantIsValid(): void
    {
        $document = json_decode(
            (string) file_get_contents(__DIR__ . '/../../../examples/kb/rule-impl.example.json'),
            false,
            512,
            JSON_THROW_ON_ERROR,
        );

        self::assertTrue($this->validator()->validate($document, $this->schema())->isValid());
    }

    public function testSuggestFixActionIsValid(): void
    {
        $document = $this->example();
        $document->spec->then[] = (object) [
            'suggest_fix' => (object) [
                'set' => (object) ['flow.protocol' => 'https'],
                'label' => 'Switch protocol to HTTPS',
            ],
        ];

        self::assertTrue($this->validator()->validate($document, $this->schema())->isValid());
    }

    /** @return iterable<string, array{callable(object): void}> */
    public static function invalidMutations(): iterable
    {
        yield 'wrong kind' => [static function (object $d): void { $d->kind = 'RiskPattern'; }];
        yield 'unknown scope' => [static function (object $d): void { $d->spec->scope = 'file'; }];
        yield 'declarative rule missing then' => [static function (object $d): void { unset($d->spec->then); }];
        yield 'declarative rule missing when' => [static function (object $d): void { unset($d->spec->when); }];
        yield 'action with neither raise nor suggest_fix' => [static function (object $d): void {
            $d->spec->then[0] = (object) ['likelihood' => 'likely'];
        }];
        yield 'action mixes raise and suggest_fix' => [static function (object $d): void {
            $d->spec->then[0]->suggest_fix = (object) ['set' => (object) ['x' => 1], 'label' => 'x'];
        }];
        yield 'raise id malformed' => [static function (object $d): void {
            $d->spec->then[0]->raise = 'data-at-rest-unencrypted';
        }];
        yield 'when.all is empty' => [static function (object $d): void { $d->spec->when->all = []; }];
        yield 'both spec.when and spec.impl present' => [static function (object $d): void {
            $d->spec->impl = 'Acme\\Rules\\SomeRule';
        }];
    }

    #[DataProvider('invalidMutations')]
    public function testInvalidDocumentsAreRejected(callable $mutate): void
    {
        $this->assertRejected($mutate);
    }
}
