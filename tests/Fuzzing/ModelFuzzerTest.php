<?php
declare(strict_types=1);
namespace HybridTM\Tests\Fuzzing;

use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Enums\Severity;
use HybridTM\Kb\YamlKbLoader;
use PHPUnit\Framework\TestCase;

/**
 * Property-based tests over ModelFuzzer (T-11.2): generates many random
 * models and checks invariants that must hold for *any* structurally
 * valid model, not just the hand-picked examples elsewhere in this
 * suite. A failure here reports the seed, so it's reproducible: rerun
 * `(new ModelFuzzer($seed))->generate()` to get the exact same model
 * back.
 */
final class ModelFuzzerTest extends TestCase
{
    private const RUNS = 200;

    public function testEncodeDecodeRoundTripIsStable(): void
    {
        $codec = new ModelJsonCodec();

        for ($seed = 1; $seed <= self::RUNS; ++$seed) {
            $model = (new ModelFuzzer($seed))->generate();

            $encodedOnce = $codec->encode($model);
            $decoded = $codec->decode($encodedOnce);
            $encodedTwice = $codec->encode($decoded);

            self::assertSame(
                $encodedOnce,
                $encodedTwice,
                "Encode->decode->encode was not stable for seed {$seed}.",
            );
        }
    }

    public function testEncodedModelIsJsonSerializable(): void
    {
        $codec = new ModelJsonCodec();

        for ($seed = 1; $seed <= self::RUNS; ++$seed) {
            $model = (new ModelFuzzer($seed))->generate();
            $encoded = $codec->encode($model);

            $json = json_encode($encoded, JSON_THROW_ON_ERROR);
            self::assertIsString($json, "Model for seed {$seed} did not encode to valid JSON.");
        }
    }

    public function testRuleEngineNeverThrowsOnAnyGeneratedModel(): void
    {
        $kb = (new YamlKbLoader())->load([__DIR__ . '/../../apps/api/kb']);
        $engine = new RuleEngine();

        for ($seed = 1; $seed <= self::RUNS; ++$seed) {
            $model = (new ModelFuzzer($seed))->generate();

            try {
                $result = $engine->analyze($model, $kb, new AnalysisOptions(minSeverity: Severity::Low));
            } catch (\Throwable $e) {
                self::fail("RuleEngine threw for seed {$seed}: {$e->getMessage()}");
            }

            self::assertIsArray($result->findings);
        }
    }

    public function testSameSeedProducesIdenticalModel(): void
    {
        $codec = new ModelJsonCodec();

        $a = $codec->encode((new ModelFuzzer(42))->generate());
        $b = $codec->encode((new ModelFuzzer(42))->generate());

        self::assertSame($a, $b, 'The same seed must reproduce the exact same model.');
    }

    public function testGeneratesBoundaryValueLengths(): void
    {
        // Not a per-seed assertion — a distributional check that the
        // fuzzer's boundary-value paths (empty and 255-char strings)
        // actually get hit across a run, not just theoretically possible.
        $sawEmpty = false;
        $sawLong = false;

        for ($seed = 1; $seed <= self::RUNS; ++$seed) {
            $model = (new ModelFuzzer($seed))->generate();
            foreach ($model->getTechnicalAssets() as $asset) {
                $value = $asset->properties->string('string_prop');
                if ($value === '') {
                    $sawEmpty = true;
                }
                if (mb_strlen($value) >= 255) {
                    $sawLong = true;
                }
            }
        }

        self::assertTrue($sawEmpty, 'Expected at least one empty-string boundary value across ' . self::RUNS . ' runs.');
        self::assertTrue($sawLong, 'Expected at least one 255-char boundary value across ' . self::RUNS . ' runs.');
    }
}
