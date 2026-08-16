<?php
declare(strict_types=1);
namespace HybridTM\Tests\Threagile;

use HybridTM\Enums\FindingSource;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;
use HybridTM\Threagile\ThreagileRiskParser;
use PHPUnit\Framework\TestCase;

final class ThreagileRiskParserTest extends TestCase
{
    private ThreagileRiskParser $parser;

    protected function setUp(): void
    {
        $this->parser = new ThreagileRiskParser();
    }

    public function testParsesRealisticRisk(): void
    {
        $json = json_encode([[
            'category' => 'unguarded-direct-datastore-access',
            'title' => 'Unguarded Direct Datastore Access',
            'severity' => 'elevated',
            'exploitation_likelihood' => 'likely',
            'exploitation_impact' => 'medium',
            'synthetic_id' => 'unguarded-direct-datastore-access@web@web@db@db',
            'most_relevant_technical_asset' => 'db',
            'risk_status' => 'unchecked',
        ]], JSON_THROW_ON_ERROR);

        $findings = $this->parser->parse($json);

        self::assertCount(1, $findings);
        $finding = $findings[0];
        self::assertSame(FindingSource::Threagile, $finding->source);
        self::assertSame('THREAGILE-unguarded-direct-datastore-access', $finding->threatId);
        self::assertSame('unguarded-direct-datastore-access', $finding->ruleId);
        self::assertSame('Unguarded Direct Datastore Access', $finding->title);
        self::assertSame(Likelihood::Likely, $finding->likelihood);
        self::assertSame(Impact::Medium, $finding->impact);
        self::assertSame('component:db', (string) $finding->subject);
        self::assertSame(['unguarded-direct-datastore-access@web@web@db@db'], $finding->evidence);
    }

    public function testFallsBackToTrustBoundaryWhenNoTechnicalAsset(): void
    {
        $json = json_encode([[
            'category' => 'missing-network-segmentation',
            'title' => 'Missing Network Segmentation',
            'most_relevant_trust_boundary' => 'dmz',
        ]], JSON_THROW_ON_ERROR);

        $finding = $this->parser->parse($json)[0];
        self::assertSame('boundary:dmz', (string) $finding->subject);
    }

    public function testFallsBackToDataAssetWhenNoAssetOrBoundary(): void
    {
        $json = json_encode([[
            'category' => 'unnecessary-data-asset',
            'title' => 'Unnecessary Data Asset',
            'most_relevant_data_asset' => 'customer-pii',
        ]], JSON_THROW_ON_ERROR);

        $finding = $this->parser->parse($json)[0];
        self::assertSame('data-asset:customer-pii', (string) $finding->subject);
    }

    public function testFallsBackToModelScopeWhenNoLocatorAtAll(): void
    {
        $json = json_encode([[
            'category' => 'missing-vault',
            'title' => 'Missing Vault',
        ]], JSON_THROW_ON_ERROR);

        $finding = $this->parser->parse($json)[0];
        self::assertSame('model:', (string) $finding->subject);
    }

    public function testUnknownLikelihoodImpactFallBackToDefaults(): void
    {
        $json = json_encode([[
            'category' => 'x',
            'title' => 'X',
            'exploitation_likelihood' => 'not-a-real-value',
            'exploitation_impact' => 'also-not-real',
        ]], JSON_THROW_ON_ERROR);

        $finding = $this->parser->parse($json)[0];
        self::assertSame(Likelihood::Likely, $finding->likelihood);
        self::assertSame(Impact::Medium, $finding->impact);
    }

    public function testParsesMultipleRisks(): void
    {
        $json = json_encode([
            ['category' => 'a', 'title' => 'A', 'most_relevant_technical_asset' => 'x'],
            ['category' => 'b', 'title' => 'B', 'most_relevant_technical_asset' => 'y'],
        ], JSON_THROW_ON_ERROR);

        self::assertCount(2, $this->parser->parse($json));
    }

    public function testEmptyArrayProducesNoFindings(): void
    {
        self::assertSame([], $this->parser->parse('[]'));
    }

    public function testMalformedJsonProducesNoFindings(): void
    {
        self::assertSame([], $this->parser->parse('not json'));
    }

    public function testParseFileReadsFromDisk(): void
    {
        $path = sys_get_temp_dir() . '/hybridtm_risks_' . uniqid('', true) . '.json';
        file_put_contents($path, json_encode([['category' => 'a', 'title' => 'A']], JSON_THROW_ON_ERROR));

        $findings = $this->parser->parseFile($path);
        self::assertCount(1, $findings);

        unlink($path);
    }
}
