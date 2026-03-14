<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum BusinessCriticality: string {
    case Archive = 'archive';
    case Operational = 'operational';
    case Important = 'important';
    case Critical = 'critical';
    case MissionCritical = 'mission-critical';
}
