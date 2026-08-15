<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/** Which engine produced a finding. */
enum FindingSource: string
{
    case HybridTM  = 'hybridtm';
    case Threagile = 'threagile';
    case Manual    = 'manual';
    case Scanner   = 'scanner';
}
