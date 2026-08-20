<?php

declare(strict_types=1);

namespace HybridTM\Kb;

/** Entity kinds recognised in knowledge-base YAML files. */
enum Kind: string
{
    case Component = 'Component';
    case Threat = 'Threat';
    case Countermeasure = 'Countermeasure';
    case Rule = 'Rule';
    case Trait = 'Trait';
    case RiskPattern = 'RiskPattern';
    case Template = 'Template';
    case Question = 'Question';
}
