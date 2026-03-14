<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Size: string {
    case System = 'system';
    case Service = 'service';
    case Application = 'application';
    case Component = 'component';
}
