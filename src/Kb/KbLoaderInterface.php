<?php

declare(strict_types=1);

namespace HybridTM\Kb;

interface KbLoaderInterface
{
    /**
     * Load and merge knowledge-base packages, later paths overriding earlier
     * ones (core KB first, organisation KB last).
     *
     * @param list<string> $paths directories containing KB YAML files
     * @throws KbException on schema violations or unresolvable references
     */
    public function load(array $paths): KnowledgeBaseInterface;
}
