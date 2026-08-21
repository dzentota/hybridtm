<?php

declare(strict_types=1);

namespace HybridTM\Analysis;

enum StoryCoverageStatus: string
{
    case Covered = 'covered';
    case Partial = 'partial';
    case Uncovered = 'uncovered';
    case Accepted = 'accepted';
}
