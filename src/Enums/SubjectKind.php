<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/** What a finding is attached to. */
enum SubjectKind: string
{
    case Component = 'component';
    case Flow      = 'flow';
    case Boundary  = 'boundary';
    case DataAsset = 'data-asset';
    case Model     = 'model';
}
