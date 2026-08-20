<?php

declare(strict_types=1);

namespace HybridTM\Kb;

/** Which pass of the analysis pipeline a rule belongs to. */
enum RuleScope: string
{
    case Component = 'component';
    case Flow = 'flow';
    case Boundary = 'boundary';
    case Model = 'model';
}
