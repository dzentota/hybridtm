<?php

declare(strict_types=1);

namespace HybridTM\Threagile;

/**
 * How a Threagile risk category relates to HybridTM's own findings (§5.4).
 */
enum MergeStrategy: string
{
    /** Both engines can find this — merge into one Finding, evidence from both, severity = max. */
    case Merge = 'merge';

    /** Only Threagile has a rule for this (yet) — import as-is with source: Threagile. */
    case ThreagileOnly = 'threagile-only';

    /** Not a risk — a model-quality problem. Goes to ValidationReport, not the risk register. */
    case ValidationOnly = 'validation';
}
