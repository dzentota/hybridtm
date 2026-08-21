<?php

declare(strict_types=1);

namespace HybridTM\Compiler;

use HybridTM\Analysis\CodeLocation;
use HybridTM\Enums\MitigationStatus;

final class DiscoveredMitigation
{
    /**
     * @param list<string> $abuserStoryIds #[AbuserStory] ids on the same class/method
     */
    public function __construct(
        public readonly string $cwe,
        public readonly string $description,
        public readonly MitigationStatus $status,
        public readonly string $context,
        public readonly ?CodeLocation $location = null,
        public readonly string $assetId = '',
        public readonly array $abuserStoryIds = [],
    ) {
    }
}
