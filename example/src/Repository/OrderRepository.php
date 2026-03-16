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
 * Data access layer for the Order aggregate (lives in order-service).
 */
#[AssetId('order-service')]
class OrderRepository
{
    /**
     * Persist a new order record within an active transaction.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data', 'customer-pii', 'payment-confirmation'],
        dataReceived: ['order-data'],
    )]
    #[Mitigation(
        cwe: 'CWE-89',
        description: 'All inserts use Doctrine ORM; no string concatenation in queries',
        status: MitigationStatus::Mitigated,
    )]
    public function save(array $order): string
    {
        return 'order-uuid';
    }

    /**
     * Fetch all orders for a user, paginated.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    public function findByUserId(string $userId, int $offset, int $limit): array
    {
        return [];
    }

    /**
     * Fetch a single order by ID.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    public function findById(string $orderId): ?array
    {
        return null;
    }

    /**
     * Update the order status and append to the status history JSON column.
     * Uses optimistic locking (version column) to prevent concurrent state transitions.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
        dataReceived: ['order-data'],
    )]
    #[Mitigation(
        cwe: 'CWE-362',
        description: 'Optimistic locking via Doctrine @Version annotation prevents lost updates on concurrent status changes',
        status: MitigationStatus::Mitigated,
    )]
    public function updateStatus(string $orderId, string $status, int $expectedVersion): bool
    {
        return true;
    }
}
