<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

use HybridTM\DSL\CommunicationLink;

/**
 * A `CommunicationLink` paired with the id of the asset it originates from.
 *
 * `CommunicationLink` itself only knows its target — the source is implicit
 * in whichever `TechnicalAsset::$communicationLinks` it lives in. `ModelIndex`
 * needs the source explicitly to answer "what flows into this asset?".
 */
final readonly class IndexedLink
{
    public string $targetAssetId;

    public function __construct(
        public string $sourceAssetId,
        public CommunicationLink $link,
    ) {
        $this->targetAssetId = $link->targetAssetId;
    }
}
