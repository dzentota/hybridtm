<?php
declare(strict_types=1);

namespace App;

use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;
use HybridTM\Attributes\Mitigation;
use HybridTM\Attributes\ProcessesData;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;

#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['user-credentials', 'user-profile'])]
class UserController
{
    #[DataFlow(
        target: 'auth-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['user-credentials'],
        dataReceived: ['session-token'],
    )]
    #[Mitigation(
        cwe: 'CWE-307',
        description: 'Rate-limit login attempts to prevent brute-force',
        status: MitigationStatus::Mitigated,
    )]
    public function login(array $credentials): array
    {
        // Implementation...
        return [];
    }

    #[DataFlow(
        target: 'user-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['user-profile'],
        dataReceived: ['user-profile'],
    )]
    public function updateProfile(string $userId, array $data): bool
    {
        // Implementation...
        return true;
    }
}
