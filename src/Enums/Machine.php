<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Machine: string {
    case Physical = 'physical';
    case Virtual = 'virtual';
    case Container = 'container';
    case Serverless = 'serverless';
}
