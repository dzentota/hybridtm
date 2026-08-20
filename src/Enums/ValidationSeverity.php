<?php

declare(strict_types=1);

namespace HybridTM\Enums;

/** Severity of a model-quality issue (distinct from risk severity). */
enum ValidationSeverity: string
{
    case Error = 'error';
    case Warning = 'warning';
    case Info = 'info';
}
