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
 * Orchestrates the full checkout flow: cart validation → payment → order creation.
 * Lives in web-app; calls order-service and Stripe (payment-provider).
 */
#[AssetId('web-app')]
#[ProcessesData(dataAssets: ['order-data', 'payment-confirmation'])]
class CheckoutController
{
    /**
     * Validate cart contents and calculate totals.
     * Delegates inventory check and pricing to order-service.
     */
    #[DataFlow(
        target: 'order-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
        dataReceived: ['order-data'],
        readonly: true,
    )]
    #[Mitigation(
        cwe: 'CWE-20',
        description: 'Cart items validated server-side; client-supplied prices are ignored — canonical prices fetched from DB',
        status: MitigationStatus::Mitigated,
    )]
    public function validateCart(string $sessionToken, array $cartItems): array
    {
        // Re-fetch canonical prices from order-service; never trust client prices
        return ['items' => $cartItems, 'total' => 99.99, 'currency' => 'USD'];
    }

    /**
     * Initiate payment via Stripe.
     *
     * Card data is tokenised client-side by Stripe.js — only a payment intent ID
     * reaches this method. Raw PAN never touches our servers.
     */
    #[DataFlow(
        target: 'payment-provider',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data'],
        dataReceived: ['payment-confirmation'],
    )]
    #[Mitigation(
        cwe: 'CWE-312',
        description: 'Raw card numbers tokenised client-side by Stripe.js; only payment intent ID sent to our backend',
        status: MitigationStatus::Mitigated,
    )]
    #[Mitigation(
        cwe: 'CWE-311',
        description: 'All Stripe API calls over TLS 1.3; API key stored in AWS Secrets Manager, rotated quarterly',
        status: MitigationStatus::Mitigated,
    )]
    #[Mitigation(
        cwe: 'CWE-352',
        description: 'Payment intent ID bound to authenticated session; CSRF token required on checkout form',
        status: MitigationStatus::Mitigated,
    )]
    public function initiatePayment(string $paymentIntentId, float $amount, string $currency): array
    {
        // Confirm payment intent with Stripe; receive confirmation object
        return ['status' => 'succeeded', 'paymentIntentId' => $paymentIntentId];
    }

    /**
     * Create the order after successful payment.
     * Publishes an order-created event; fulfilment is handled asynchronously.
     */
    #[DataFlow(
        target: 'order-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataSent: ['order-data', 'payment-confirmation'],
        dataReceived: ['order-data'],
    )]
    #[Mitigation(
        cwe: 'CWE-362',
        description: 'Idempotency key on order creation prevents duplicate charges if the client retries',
        status: MitigationStatus::Mitigated,
    )]
    public function placeOrder(string $userId, array $cartItems, array $paymentResult): array
    {
        // Call order-service; it persists the order and emits domain events
        return ['orderId' => 'order-uuid', 'status' => 'confirmed'];
    }

    /**
     * Retrieve order history for the authenticated user.
     */
    #[DataFlow(
        target: 'order-service',
        protocol: Protocol::Https,
        authentication: Authentication::Token,
        authorization: Authorization::TechnicalUser,
        dataReceived: ['order-data'],
        readonly: true,
    )]
    public function getOrderHistory(string $userId, int $page = 1, int $limit = 20): array
    {
        return ['orders' => [], 'total' => 0];
    }
}
