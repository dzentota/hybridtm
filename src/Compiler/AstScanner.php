<?php
declare(strict_types=1);
namespace HybridTM\Compiler;

use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\ErrorHandler\Collecting;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class AstScanner
{
    public function scan(string $directory): AstResult
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $visitor = new DataFlowVisitor();
        $traverser = new NodeTraverser();
        $traverser->addVisitor($visitor);

        $warnings = [];

        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
        foreach ($it as $file) {
            if (!($file instanceof SplFileInfo) || $file->getExtension() !== 'php') {
                continue;
            }

            $code = file_get_contents($file->getPathname());
            if ($code === false) continue;

            $errorHandler = new Collecting();
            $stmts = $parser->parse($code, $errorHandler);

            if ($stmts === null || $errorHandler->hasErrors()) {
                $errors = array_map(fn($e) => $e->getMessage(), $errorHandler->getErrors());
                $warnings[] = "Parse error in {$file->getPathname()}: " . implode('; ', $errors);
                if ($stmts === null) continue;
            }

            $traverser->traverse($stmts);
        }

        $result = $visitor->getResult();
        return new AstResult(
            $result->dataFlows,
            $result->mitigations,
            $result->processesData,
            array_merge($result->warnings, $warnings),
        );
    }
}
