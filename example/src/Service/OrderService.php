<?php
declare(strict_types=1);
namespace App\Service;

use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;
use HybridTM\Attributes\Mitigation;
use HybridTM\Attributes\ProcessesData;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;

/**
 * Order domain service.
 * Owns the order aggregate: creation, validation, status transitions, and persistence.
 * Publishes domain events to RabbitMQ for async downstream processing.
 */
#[AssetId('order-service')]
#[ProcessesData(dataAssets: ['order-data', 'customer-pii', 'payment-confirmation'])]
class OrderService
{
    /**
     * Create a new order from a validated cart and confirmed payment.
     * Persists the order and publishes an order.created event.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data', 'payment-confirmation'],
        dataReceived: ['order-data'],
    )]
    #[DataFlow(
        target: 'message-queue',
        protocol: Protocol::Jms,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
    )]
    #[Mitigation(
        cwe: 'CWE-362',
        description: 'Order creation is wrapped in a DB transaction; message published only after commit (outbox pattern)',
        status: MitigationStatus::Mitigated,
    )]
    public function createOrder(string $userId, array $items, array $paymentResult): array
    {
        // 1. Begin transaction
        // 2. Persist order record with payment_intent_id
        // 3. Write to outbox table
        // 4. Commit transaction
        // 5. Relay worker picks up outbox and publishes to RabbitMQ
        return ['orderId' => 'order-uuid', 'status' => 'confirmed'];
    }

    /**
     * Look up all orders for a given user.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    public function findByUserId(string $userId, int $page = 1, int $limit = 20): array
    {
        return [];
    }

    /**
     * Get a single order by ID, asserting ownership.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    #[Mitigation(
        cwe: 'CWE-639',
        description: 'Ownership assertion: userId in JWT must match order.user_id; no IDOR possible',
        status: MitigationStatus::Mitigated,
    )]
    public function findById(string $orderId, string $requestingUserId): ?array
    {
        return null;
    }

    /**
     * Transition an order to a new status (e.g. shipped, delivered, cancelled).
     * Publishes a status-changed event so downstream services stay in sync.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
        dataReceived: ['order-data'],
    )]
    #[DataFlow(
        target: 'message-queue',
        protocol: Protocol::Jms,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
    )]
    public function updateStatus(string $orderId, string $newStatus, string $reason = ''): void
    {
        // State machine guards; only valid transitions are allowed
    }

    /**
     * Cancel an order and initiate a refund request to the payment provider.
     * The actual refund call is handled by web-app → payment-provider.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
    )]
    #[DataFlow(
        target: 'message-queue',
        protocol: Protocol::Jms,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data', 'payment-confirmation'],
    )]
    #[Mitigation(
        cwe: 'CWE-362',
        description: 'Cancellation guarded by optimistic locking (version column); concurrent cancel+ship prevented',
        status: MitigationStatus::Mitigated,
    )]
    public function cancelOrder(string $orderId, string $userId, string $reason): array
    {
        return ['orderId' => $orderId, 'status' => 'cancelled', 'refundInitiated' => true];
    }
}
