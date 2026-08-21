<?php

declare(strict_types=1);

namespace HybridTM\Codec;

use PhpParser\ErrorHandler\Collecting;
use PhpParser\ParserFactory;

/**
 * Parses a `threat-model.php` file's source via AST (ADR-08) and hands its
 * top-level statements to `DslVisitor` — never `require`s the file, which
 * would execute arbitrary code and is only ever safe in a trusted CLI
 * context, not e.g. a multi-tenant web service accepting uploaded DSL.
 */
final class PhpDslReader
{
    public function read(string $code): DslReadResult
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $errorHandler = new Collecting();
        $stmts = $parser->parse($code, $errorHandler);

        if ($stmts === null || $errorHandler->hasErrors()) {
            $messages = array_map(static fn ($e): string => $e->getMessage(), $errorHandler->getErrors());
            return new DslReadResult(null, [new NonCanonicalConstruct(1, 'parse error: ' . implode('; ', $messages))]);
        }

        return (new DslVisitor())->read(array_values($stmts));
    }

    public function readFile(string $path): DslReadResult
    {
        $code = file_get_contents($path);
        if ($code === false) {
            return new DslReadResult(null, [new NonCanonicalConstruct(1, "could not read file: {$path}")]);
        }

        return $this->read($code);
    }
}
