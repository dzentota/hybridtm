<?php

declare(strict_types=1);

namespace App\Report;

use HybridTM\Analysis\AnalysisResult;
use HybridTM\DSL\ThreatModel;

/**
 * Everything the PDF/DOCX/XLSX generators need, assembled once by
 * ReportController so each generator is a pure function of this struct —
 * no generator talks to Doctrine or the RuleEngine directly.
 */
final readonly class ReportData
{
    public function __construct(
        public string $projectTitle,
        public string $modelTitle,
        public ThreatModel $model,
        public AnalysisResult $result,
        public \DateTimeImmutable $generatedAt,
    ) {
    }
}
