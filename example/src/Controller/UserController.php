<?php
declare(strict_types=1);
namespace App\Controller;

use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;
use HybridTM\Attributes\Mitigation;
use HybridTM\Attributes\ProcessesData;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;

/**
 * Handles user registration, login, profile management, and account deletion.
 * Lives in the web-app (Symfony BFF) and calls auth-service and main-db.
 */
#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['customer-pii', 'user-credentials', 'session-token'])]
class UserController
{
    /**
     * Register a new user account.
     * Writes PII and hashed credentials to the database.
     * Triggers a welcome email via the notification service.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii', 'user-credentials'],
    )]
    #[DataFlow(
        target: 'notification-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['notification-payload'],
    )]
    #[Mitigation(
        cwe: 'CWE-521',
        description: 'Password strength enforced server-side: min 12 chars, complexity rules, HaveIBeenPwned check',
        status: MitigationStatus::Mitigated,
    )]
    #[Mitigation(
        cwe: 'CWE-916',
        description: 'Passwords hashed with bcrypt cost=12 before persistence; plaintext never logged or stored',
        status: MitigationStatus::Mitigated,
    )]
    public function register(string $email, string $password, array $profile): array
    {
        // 1. Validate input (Symfony Validator)
        // 2. Check email uniqueness
        // 3. Hash password with bcrypt
        // 4. Persist user record
        // 5. Publish welcome email via notification-service
        return ['id' => 'user-uuid', 'email' => $email];
    }

    /**
     * Authenticate a user and issue a session token.
     * Delegates credential verification to auth-service.
     */
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
        description: 'Login attempts rate-limited to 5/min per IP via Redis token bucket; account locked after 10 failures',
        status: MitigationStatus::Mitigated,
    )]
    #[Mitigation(
        cwe: 'CWE-598',
        description: 'Credentials transmitted only in POST body over TLS; never in URL query string',
        status: MitigationStatus::Mitigated,
    )]
    public function login(string $email, string $password): array
    {
        // 1. Rate-limit check (Redis token bucket)
        // 2. Forward credentials to auth-service
        // 3. Receive JWT and set HttpOnly cookie
        return ['token' => 'jwt-string', 'expiresAt' => time() + 3600];
    }

    /**
     * Retrieve the authenticated user's profile.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['customer-pii'],
        readonly: true,
    )]
    public function getProfile(string $userId): array
    {
        return ['id' => $userId, 'email' => 'user@example.com'];
    }

    /**
     * Update mutable profile fields (name, address, phone).
     * Email and password changes go through separate verified flows.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii'],
        dataReceived: ['customer-pii'],
    )]
    #[Mitigation(
        cwe: 'CWE-20',
        description: 'Profile fields validated and sanitised via Symfony Validator before persistence',
        status: MitigationStatus::Mitigated,
    )]
    public function updateProfile(string $userId, array $data): bool
    {
        return true;
    }

    /**
     * Hard-delete all personal data for GDPR right-to-erasure requests.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['customer-pii', 'user-credentials', 'order-data'],
    )]
    #[DataFlow(
        target: 'auth-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['session-token'],
    )]
    #[Mitigation(
        cwe: 'CWE-212',
        description: 'Deletion cascades across all tables; session invalidated before DB delete; audit log retained for legal hold',
        status: MitigationStatus::Mitigated,
    )]
    public function deleteAccount(string $userId): void
    {
        // 1. Invalidate all active sessions via auth-service
        // 2. Anonymise order history (retain for accounting)
        // 3. Hard-delete PII columns
        // 4. Emit GDPR audit event
    }

    /**
     * Invalidate the current session (logout).
     */
    #[DataFlow(
        target: 'auth-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['session-token'],
    )]
    public function logout(string $sessionToken): void
    {
        // Revoke token in auth-service; clear HttpOnly cookie
    }
}
