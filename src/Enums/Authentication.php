<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Authentication: string {
    case None = 'none';
    case Credentials = 'credentials';
    case SessionId = 'session-id';
    case Token = 'token';
    case ClientCertificate = 'client-certificate';
    case TwoFactor = 'two-factor';
    case ExternalizedViaGateway = 'externalized-via-gateway';
}
