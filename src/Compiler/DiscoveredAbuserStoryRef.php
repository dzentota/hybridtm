<?php

declare(strict_types=1);

namespace HybridTM\Compiler;

use HybridTM\Analysis\CodeLocation;

/** A #[AbuserStory('id')] reference discovered on a class or method. */
final class DiscoveredAbuserStoryRef
{
    /**
     * @param list<string> $siblingCwes CWEs from #[Mitigation] on the same context
     */
    public function __construct(
        public readonly string $storyId,
        public readonly string $context,
        public readonly string $assetId = '',
        public readonly array $siblingCwes = [],
        public readonly ?CodeLocation $location = null,
    ) {
    }
}
