<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Encryption: string {
    case None = 'none';
    case Transparent = 'transparent';
    case SymmetricSharedKey = 'symmetric-shared-key';
    case AsymmetricSharedKey = 'asymmetric-shared-key';
    case EndToEnd = 'end-to-end';
    case EndToEndOwnData = 'end-to-end-own-data';
}
