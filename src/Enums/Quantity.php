<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Quantity: string {
    case VeryFew = 'very-few';
    case Few = 'few';
    case Many = 'many';
    case VeryMany = 'very-many';
}
