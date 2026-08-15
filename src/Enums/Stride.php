<?php
declare(strict_types=1);
namespace HybridTM\Enums;

/** STRIDE categories. Values match Threagile `types.STRIDE`. */
enum Stride: string
{
    case Spoofing              = 'spoofing';
    case Tampering             = 'tampering';
    case Repudiation           = 'repudiation';
    case InformationDisclosure = 'information-disclosure';
    case DenialOfService       = 'denial-of-service';
    case ElevationOfPrivilege  = 'elevation-of-privilege';

    /** Security property the category threatens. */
    public function property(): string
    {
        return match ($this) {
            self::Spoofing              => 'Authenticity',
            self::Tampering             => 'Integrity',
            self::Repudiation           => 'Non-repudiability',
            self::InformationDisclosure => 'Confidentiality',
            self::DenialOfService       => 'Availability',
            self::ElevationOfPrivilege  => 'Authorization',
        };
    }
}
