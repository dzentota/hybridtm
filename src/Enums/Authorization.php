<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Authorization: string {
    case None = 'none';
    case TechnicalUser = 'technical-user';
    case EnduserIdentityPropagation = 'enduser-identity-propagation';
}
