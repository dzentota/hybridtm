<?php

declare(strict_types=1);

namespace HybridTM\Enums;

enum AbuseCaseStatus: string
{
    case Open = 'open';
    case InProgress = 'in-progress';
    case Mitigated = 'mitigated';
    case Accepted = 'accepted';
}
