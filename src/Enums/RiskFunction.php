<?php

declare(strict_types=1);

namespace HybridTM\Enums;

/** Who owns closing an individual risk category. Matches Threagile `types.RiskFunction`. */
enum RiskFunction: string
{
    case BusinessSide = 'business-side';
    case Architecture = 'architecture';
    case Development = 'development';
    case Operations = 'operations';
}
