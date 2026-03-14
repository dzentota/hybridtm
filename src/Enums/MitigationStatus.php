<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum MitigationStatus: string {
    case Accepted = 'accepted';
    case InProgress = 'in-progress';
    case Mitigated = 'mitigated';
    case Unchecked = 'unchecked';
}
