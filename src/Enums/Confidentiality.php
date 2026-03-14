<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Confidentiality: string {
    case Public = 'public';
    case Internal = 'internal';
    case Restricted = 'restricted';
    case Confidential = 'confidential';
    case StrictlyConfidential = 'strictly-confidential';
}
