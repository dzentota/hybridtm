<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum AssetType: string {
    case ExternalEntity = 'external-entity';
    case Process = 'process';
    case Datastore = 'datastore';
}
