<?php
declare(strict_types=1);
namespace HybridTM\Validation\Rules;

/**
 * Convention for recording which KB component a `TechnicalAsset` was
 * expanded from: a tag of the form `kb-component:<id>` or
 * `kb-component:<id>@<version>`. This is the "marker" tier of the
 * KB-recognition strategy described in §6.3 (marker → tag → heuristic →
 * fallback) — cheap to check before the real `ComponentExpander` (T-2.10)
 * and its reverse-recognition counterpart (T-2.11) land.
 */
final readonly class KbComponentTag
{
    private function __construct(
        public string $componentId,
        public ?string $version,
    ) {
    }

    /** @param string[] $tags */
    public static function fromTags(array $tags): ?self
    {
        foreach ($tags as $tag) {
            if (!str_starts_with($tag, 'kb-component:')) {
                continue;
            }

            $value = substr($tag, strlen('kb-component:'));
            [$id, $version] = str_contains($value, '@')
                ? explode('@', $value, 2)
                : [$value, null];

            return new self($id, $version);
        }

        return null;
    }
}
