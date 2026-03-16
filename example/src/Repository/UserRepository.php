<?php
declare(strict_types=1);
namespace App\Repository;

use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;
use HybridTM\Attributes\Mitigation;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;

/**
 * Data access layer for the User aggregate.
 * All queries use Doctrine ORM parameterised statements — no raw SQL with user input.
 */
#[AssetId('web-app')]
class UserRepository
{
    /**
     * Look up a user by primary key.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['customer-pii', 'user-credentials'],
        readonly: true,
    )]
    public function findById(string $id): ?array
    {
        return null;
    }

    /**
     * Look up a user by email address (used during login and registration).
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['customer-pii', 'user-credentials'],
        readonly: true,
    )]
    #[Mitigation(
        cwe: 'CWE-89',
        description: 'Email lookup uses Doctrine DQL with named parameter binding; immune to SQL injection',
        status: MitigationStatus::Mitigated,
    )]
    public function findByEmail(string $email): ?array
    {
        return null;
    }

    /**
     * Persist a new user record (registration).
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii', 'user-credentials'],
        dataReceived: ['customer-pii'],
    )]
    #[Mitigation(
        cwe: 'CWE-89',
        description: 'All inserts use Doctrine ORM entity mapping; no raw SQL',
        status: MitigationStatus::Mitigated,
    )]
    public function save(array $user): string
    {
        return 'new-user-uuid';
    }

    /**
     * Update mutable profile fields.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii'],
    )]
    public function updateProfile(string $id, array $fields): void
    {
        // Doctrine ORM merge
    }

    /**
     * Hard-delete a user row (GDPR right to erasure).
     * Cascades to associated tables via DB foreign-key constraints.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii', 'user-credentials'],
    )]
    #[Mitigation(
        cwe: 'CWE-212',
        description: 'Deletion cascades via FK constraints; audit log row retained with anonymised user_id for legal hold',
        status: MitigationStatus::Mitigated,
    )]
    public function delete(string $id): void
    {
        // Doctrine ORM remove + flush inside a transaction
    }
}
