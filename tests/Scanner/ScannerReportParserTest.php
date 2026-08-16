<?php
declare(strict_types=1);
namespace HybridTM\Tests\Scanner;

use HybridTM\Scanner\ScannerReportParser;
use PHPUnit\Framework\TestCase;

final class ScannerReportParserTest extends TestCase
{
    private ScannerReportParser $parser;

    protected function setUp(): void
    {
        $this->parser = new ScannerReportParser();
    }

    public function testParsesCheckovPassedAndFailedChecks(): void
    {
        $json = json_encode([
            'results' => [
                'passed_checks' => [
                    ['check_id' => 'CKV_AWS_16', 'resource' => 'aws_db_instance.main'],
                ],
                'failed_checks' => [
                    ['check_id' => 'CKV_AWS_17', 'resource' => 'aws_db_instance.main'],
                ],
            ],
        ]);

        $findings = $this->parser->parse('checkov', $json);

        self::assertCount(2, $findings);
        self::assertSame('checkov', $findings[0]->tool);
        self::assertSame('CKV_AWS_16', $findings[0]->ruleId);
        self::assertTrue($findings[0]->passed);
        self::assertSame('aws_db_instance.main', $findings[0]->resource);
        self::assertFalse($findings[1]->passed);
    }

    public function testParsesTrivyMisconfigurationsByStatus(): void
    {
        $json = json_encode([
            'Results' => [
                [
                    'Target' => 'main.tf',
                    'Misconfigurations' => [
                        ['ID' => 'AVD-AWS-0028', 'Status' => 'PASS'],
                        ['ID' => 'AVD-AWS-0029', 'Status' => 'FAIL'],
                    ],
                ],
            ],
        ]);

        $findings = $this->parser->parse('trivy', $json);

        self::assertCount(2, $findings);
        self::assertSame('trivy', $findings[0]->tool);
        self::assertSame('main.tf', $findings[0]->resource);
        self::assertTrue($findings[0]->passed);
        self::assertFalse($findings[1]->passed);
    }

    public function testParsesSonarQubeIssuesTreatingResolvedAsPassed(): void
    {
        $json = json_encode([
            'issues' => [
                ['rule' => 'phpsecurity:S1234', 'status' => 'RESOLVED', 'component' => 'src/Foo.php'],
                ['rule' => 'phpsecurity:S5678', 'status' => 'OPEN', 'component' => 'src/Bar.php'],
            ],
        ]);

        $findings = $this->parser->parse('sonarqube', $json);

        self::assertCount(2, $findings);
        self::assertTrue($findings[0]->passed);
        self::assertFalse($findings[1]->passed);
    }

    public function testUnknownToolThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->parser->parse('nessus', '{}');
    }

    public function testInvalidJsonThrows(): void
    {
        $this->expectException(\JsonException::class);
        $this->parser->parse('checkov', 'not json');
    }
}
