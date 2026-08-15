<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

use HybridTM\DSL\ThreatModel;
use HybridTM\Kb\KnowledgeBaseInterface;

/**
 * The analyzer is a pure function: the same model, knowledge base and
 * options must always produce byte-identical output. That property is what
 * makes caching by input hash, golden-file testing and reproducible CI
 * results possible — do not introduce clocks, randomness or I/O behind it.
 */
interface AnalyzerInterface
{
    public function analyze(
        ThreatModel $model,
        KnowledgeBaseInterface $kb,
        AnalysisOptions $options = new AnalysisOptions(),
    ): AnalysisResult;
}
