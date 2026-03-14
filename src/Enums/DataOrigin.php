<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum DataOrigin: string {
    case Unknown = 'unknown';
    case FileImport = 'file-import';
    case UserInput = 'ui-input';
    case DeviceAccess = 'device-access';
    case ServiceCall = 'service-call';
    case TransferredFromPartner = 'transferred-from-partner';
    case InHouse = 'in-house';
}
