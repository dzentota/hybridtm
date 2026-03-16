<?php
declare(strict_types=1);
namespace App\Consumer;

use HybridTM\Attributes\AssetId;
use HybridTM\Attributes\DataFlow;
use HybridTM\Attributes\Mitigation;
use HybridTM\Attributes\ProcessesData;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;

/**
 * Async worker that consumes order.created events from RabbitMQ.
 *
 * Responsibilities:
 *   1. Trigger a transactional confirmation email via notification-service.
 *   2. Update fulfilment status in the database.
 *
 * Runs inside order-service as a long-lived Symfony Messenger worker.
 */
#[AssetId('order-service')]
#[ProcessesData(dataAssets: ['order-data', 'customer-pii', 'notification-payload'])]
class OrderProcessedConsumer
{
    /**
     * Entry point for incoming order.created messages from RabbitMQ.
     * The message is acknowledged only after both downstream calls succeed.
     */
    #[DataFlow(
        target: 'message-queue',
        protocol: Protocol::Jms,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    #[Mitigation(
        cwe: 'CWE-400',
        description: 'Message payload size capped at 64 KB; malformed JSON causes DLQ routing, not process crash',
        status: MitigationStatus::Mitigated,
    )]
    public function __invoke(array $message): void
    {
        // 1. Validate and deserialise the message
        // 2. Call notifyCustomer() — sends confirmation email
        // 3. Call updateFulfilmentStatus()
        // 4. ACK the message (Symfony Messenger does this automatically on success)
        $this->notifyCustomer($message);
        $this->updateFulfilmentStatus($message['orderId'], 'processing');
    }

    /**
     * Fire a transactional notification via notification-service.
     * Passes the order summary and customer email for template rendering.
     */
    #[DataFlow(
        target: 'notification-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['notification-payload', 'customer-pii'],
    )]
    #[Mitigation(
        cwe: 'CWE-502',
        description: 'Notification payload assembled from validated DB data, not from raw message body, to prevent injection via queue',
        status: MitigationStatus::Mitigated,
    )]
    private function notifyCustomer(array $orderMessage): void
    {
        // Build payload from order data; call notification-service REST endpoint
    }

    /**
     * Persist the updated fulfilment status back to the database.
     */
    #[DataFlow(
        target: 'main-db',
        protocol: Protocol::JdbcEncrypted,
        authentication: Authentication::Credentials,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
    )]
    private function updateFulfilmentStatus(string $orderId, string $status): void
    {
        // Doctrine ORM update
    }
}
