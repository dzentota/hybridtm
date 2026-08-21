<?php

declare(strict_types=1);

namespace HybridTM\Tests\Schema;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The canonical JSON schema and the PHP enums are two copies of the same
 * vocabulary. This test is the drift guard: add a case to an enum and forget
 * the schema, and the build fails here rather than at a customer's import.
 */
final class SchemaEnumConsistencyTest extends TestCase
{
    private const SCHEMA = __DIR__ . '/../../schema/canonical-model.v1.json';

    /** @return iterable<string, array{string, class-string}> */
    public static function pairs(): iterable
    {
        $map = [
            'modelMeta.properties.businessCriticality' => \HybridTM\Enums\BusinessCriticality::class,
            'dataAsset.properties.usage' => \HybridTM\Enums\DataUsage::class,
            'dataAsset.properties.origin' => \HybridTM\Enums\DataOrigin::class,
            'dataAsset.properties.quantity' => \HybridTM\Enums\Quantity::class,
            'dataAsset.properties.confidentiality' => \HybridTM\Enums\Confidentiality::class,
            'dataAsset.properties.integrity' => \HybridTM\Enums\Integrity::class,
            'dataAsset.properties.availability' => \HybridTM\Enums\Availability::class,
            'component.properties.overrides.properties.type' => \HybridTM\Enums\AssetType::class,
            'component.properties.overrides.properties.technology' => \HybridTM\Enums\Technology::class,
            'component.properties.overrides.properties.machine' => \HybridTM\Enums\Machine::class,
            'component.properties.overrides.properties.size' => \HybridTM\Enums\Size::class,
            'component.properties.overrides.properties.encryption' => \HybridTM\Enums\Encryption::class,
            'trustBoundary.properties.type' => \HybridTM\Enums\TrustBoundaryType::class,
            'dataFlow.properties.protocol' => \HybridTM\Enums\Protocol::class,
            'dataFlow.properties.authentication' => \HybridTM\Enums\Authentication::class,
            'dataFlow.properties.authorization' => \HybridTM\Enums\Authorization::class,
            'riskDecision.properties.status' => \HybridTM\Enums\DecisionStatus::class,
        ];

        foreach ($map as $path => $enum) {
            yield $path => [$path, $enum];
        }
    }

    /** @param class-string $enumClass */
    #[DataProvider('pairs')]
    public function testSchemaEnumMatchesPhpEnum(string $path, string $enumClass): void
    {
        $node = self::resolve($path);

        self::assertArrayHasKey('enum', $node, "Schema node \$defs.{$path} has no enum list.");
        self::assertSame(
            array_map(static fn (\BackedEnum $c): string|int => $c->value, $enumClass::cases()),
            $node['enum'],
            "Schema \$defs.{$path} is out of sync with {$enumClass}.",
        );
    }

    public function testSchemaIsValidJsonAndPinsVersion(): void
    {
        $schema = self::schema();

        self::assertSame(1, $schema['properties']['schemaVersion']['const']);
        self::assertSame('https://json-schema.org/draft/2020-12/schema', $schema['$schema']);
    }

    /** @return array<string, mixed> */
    private static function schema(): array
    {
        $raw = file_get_contents(self::SCHEMA);
        self::assertIsString($raw, 'Canonical schema file is missing.');

        return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    }

    /** @return array<string, mixed> */
    private static function resolve(string $dotPath): array
    {
        $node = self::schema()['$defs'];
        foreach (explode('.', $dotPath) as $segment) {
            self::assertArrayHasKey($segment, $node, "Cannot resolve segment '{$segment}' of '{$dotPath}'.");
            $node = $node[$segment];
        }

        return $node;
    }
}
