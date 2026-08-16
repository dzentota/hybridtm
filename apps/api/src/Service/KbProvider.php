<?php

declare(strict_types=1);

namespace App\Service;

use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Kb\YamlKbLoader;

/**
 * Loads and memoizes the merged knowledge base for this process (T-6.2).
 * A real compiled-cache loader (T-2.4) doesn't exist yet — this just
 * avoids re-parsing every KB YAML file on every call within one request/
 * worker lifetime, which is enough for a dev seed KB of a handful of files.
 */
final class KbProvider
{
    private ?KnowledgeBaseInterface $kb = null;

    /** @param list<string> $kbPaths */
    public function __construct(
        private readonly array $kbPaths,
        private readonly YamlKbLoader $loader = new YamlKbLoader(),
    ) {
    }

    public function get(): KnowledgeBaseInterface
    {
        return $this->kb ??= $this->loader->load($this->kbPaths);
    }
}
