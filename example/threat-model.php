<?php
/**
 * HybridTM Example — E-Commerce Platform
 *
 * Threat model for a cloud-native PHP e-commerce platform consisting of:
 *   - A web application (Symfony monolith acting as BFF)
 *   - An Auth microservice
 *   - An Order microservice
 *   - A Notification microservice
 *   - PostgreSQL, Redis, and RabbitMQ as backing services
 *   - Stripe as the external payment provider
 *
 * Run:
 *   php bin/hybridtm compile \
 *       --infra=example/threat-model.php \
 *       --source=example/src/ \
 *       --out=build/threagile.yaml
 */
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\AssetType;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Availability;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\Size;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;

// ── Model metadata ────────────────────────────────────────────────────────────

$model = new ThreatModel('E-Commerce Platform');
$model->description         = 'Threat model for a cloud-native PHP e-commerce platform.';
$model->author              = 'Platform Security Team';
$model->date                = '2024-01-15';
$model->businessCriticality = BusinessCriticality::Critical;
$model->managementSummaryComment = 'PCI DSS in scope for payment flows. GDPR in scope for EU customer data.';

// ── Data Assets ───────────────────────────────────────────────────────────────

$customerPii = new DataAsset('customer-pii', 'Customer PII');
$customerPii->description         = 'Name, email, shipping/billing address — GDPR sensitive';
$customerPii->confidentiality     = Confidentiality::Confidential;
$customerPii->integrity           = Integrity::Important;
$customerPii->availability        = Availability::Important;
$customerPii->origin              = DataOrigin::UserInput;
$customerPii->quantity            = Quantity::VeryMany;
$customerPii->justificationCiaRating = 'GDPR Article 4 personal data; breach triggers 72h notification.';
$model->addDataAsset($customerPii);

$userCredentials = new DataAsset('user-credentials', 'User Credentials');
$userCredentials->description     = 'Bcrypt-hashed passwords; never stored in plaintext';
$userCredentials->confidentiality = Confidentiality::StrictlyConfidential;
$userCredentials->integrity       = Integrity::Critical;
$userCredentials->availability    = Availability::Critical;
$userCredentials->origin          = DataOrigin::UserInput;
$userCredentials->quantity        = Quantity::Many;
$model->addDataAsset($userCredentials);

$sessionToken = new DataAsset('session-token', 'Session Token (JWT)');
$sessionToken->description     = 'Short-lived JWT signed with RS256; stored in HttpOnly cookie';
$sessionToken->confidentiality = Confidentiality::StrictlyConfidential;
$sessionToken->integrity       = Integrity::Critical;
$sessionToken->availability    = Availability::Operational;
$sessionToken->origin          = DataOrigin::InHouse;
$sessionToken->quantity        = Quantity::VeryMany;
$model->addDataAsset($sessionToken);

$orderData = new DataAsset('order-data', 'Order Data');
$orderData->description     = 'Cart contents, order status, fulfilment history';
$orderData->confidentiality = Confidentiality::Internal;
$orderData->integrity       = Integrity::Critical;
$orderData->availability    = Availability::Critical;
$orderData->origin          = DataOrigin::UserInput;
$orderData->quantity        = Quantity::VeryMany;
$model->addDataAsset($orderData);

$paymentConfirmation = new DataAsset('payment-confirmation', 'Payment Confirmation');
$paymentConfirmation->description     = 'Payment intent ID, status, and masked card last4 returned by Stripe — no raw PAN ever stored';
$paymentConfirmation->confidentiality = Confidentiality::Restricted;
$paymentConfirmation->integrity       = Integrity::MissionCritical;
$paymentConfirmation->availability    = Availability::Critical;
$paymentConfirmation->origin          = DataOrigin::ServiceCall;
$paymentConfirmation->quantity        = Quantity::Many;
$paymentConfirmation->justificationCiaRating = 'PCI DSS: raw card data tokenised client-side by Stripe.js; we only receive a token.';
$model->addDataAsset($paymentConfirmation);

$notificationPayload = new DataAsset('notification-payload', 'Notification Payload');
$notificationPayload->description     = 'Transactional email/SMS content: order confirmations, password resets';
$notificationPayload->confidentiality = Confidentiality::Internal;
$notificationPayload->integrity       = Integrity::Important;
$notificationPayload->availability    = Availability::Important;
$notificationPayload->origin          = DataOrigin::InHouse;
$notificationPayload->quantity        = Quantity::VeryMany;
$model->addDataAsset($notificationPayload);

// ── Technical Assets ──────────────────────────────────────────────────────────

// -- External entities --

$browser = new TechnicalAsset('browser', 'User Browser');
$browser->type                = AssetType::ExternalEntity;
$browser->technology          = Technology::Browser;
$browser->size                = Size::Component;
$browser->usedAsClientByHuman = true;
$browser->internet            = true;
$browser->machine             = Machine::Physical;
$browser->confidentiality     = Confidentiality::Public;
$browser->integrity           = Integrity::Operational;
$browser->availability        = Availability::Operational;
$model->addTechnicalAsset($browser);

$paymentProvider = new TechnicalAsset('payment-provider', 'Stripe (Payment Gateway)');
$paymentProvider->type          = AssetType::ExternalEntity;
$paymentProvider->technology    = Technology::WebServiceRest;
$paymentProvider->internet      = true;
$paymentProvider->machine       = Machine::Virtual;
$paymentProvider->size          = Size::System;
$paymentProvider->confidentiality = Confidentiality::StrictlyConfidential;
$paymentProvider->integrity     = Integrity::MissionCritical;
$paymentProvider->availability  = Availability::Critical;
$model->addTechnicalAsset($paymentProvider);

// -- Internal services --

$webApp = new TechnicalAsset('web-app', 'Web Application (Symfony BFF)');
$webApp->type                 = AssetType::Process;
$webApp->technology           = Technology::WebApplication;
$webApp->size                 = Size::Service;
$webApp->machine              = Machine::Container;
$webApp->customDevelopedParts = true;
$webApp->internet             = true; // exposed via load balancer
$webApp->confidentiality      = Confidentiality::Confidential;
$webApp->integrity            = Integrity::Critical;
$webApp->availability         = Availability::Critical;
$webApp->owner                = 'Backend Team';
$webApp->dataAssetsProcessed  = ['customer-pii', 'user-credentials', 'session-token', 'order-data'];
$model->addTechnicalAsset($webApp);

$authService = new TechnicalAsset('auth-service', 'Auth Microservice');
$authService->type                 = AssetType::Process;
$authService->technology           = Technology::WebServiceRest;
$authService->size                 = Size::Service;
$authService->machine              = Machine::Container;
$authService->customDevelopedParts = true;
$authService->confidentiality      = Confidentiality::Confidential;
$authService->integrity            = Integrity::MissionCritical;
$authService->availability         = Availability::Critical;
$authService->owner                = 'Security Team';
$authService->dataAssetsProcessed  = ['user-credentials', 'session-token'];
$model->addTechnicalAsset($authService);

$orderService = new TechnicalAsset('order-service', 'Order Microservice');
$orderService->type                 = AssetType::Process;
$orderService->technology           = Technology::WebServiceRest;
$orderService->size                 = Size::Service;
$orderService->machine              = Machine::Container;
$orderService->customDevelopedParts = true;
$orderService->confidentiality      = Confidentiality::Internal;
$orderService->integrity            = Integrity::Critical;
$orderService->availability         = Availability::Critical;
$orderService->owner                = 'Orders Team';
$orderService->dataAssetsProcessed  = ['order-data', 'customer-pii'];
$model->addTechnicalAsset($orderService);

$notificationService = new TechnicalAsset('notification-service', 'Notification Microservice');
$notificationService->type                 = AssetType::Process;
$notificationService->technology           = Technology::WebServiceRest;
$notificationService->size                 = Size::Service;
$notificationService->machine              = Machine::Container;
$notificationService->customDevelopedParts = true;
$notificationService->confidentiality      = Confidentiality::Internal;
$notificationService->integrity            = Integrity::Important;
$notificationService->availability         = Availability::Important;
$notificationService->owner                = 'Platform Team';
$notificationService->dataAssetsProcessed  = ['notification-payload', 'customer-pii'];
$model->addTechnicalAsset($notificationService);

// -- Data stores --

$mainDb = new TechnicalAsset('main-db', 'PostgreSQL (Main Database)');
$mainDb->type             = AssetType::Datastore;
$mainDb->technology       = Technology::Database;
$mainDb->size             = Size::System;
$mainDb->machine          = Machine::Virtual;
$mainDb->encryption       = Encryption::DataWithSymmetricSharedKey;
$mainDb->confidentiality  = Confidentiality::StrictlyConfidential;
$mainDb->integrity        = Integrity::Critical;
$mainDb->availability     = Availability::Critical;
$mainDb->owner            = 'DBA Team';
$mainDb->dataAssetsStored = ['customer-pii', 'user-credentials', 'order-data', 'payment-confirmation'];
$mainDb->justificationCiaRating = 'Primary system of record; encrypted at rest via AWS RDS with KMS.';
$model->addTechnicalAsset($mainDb);

$redisCache = new TechnicalAsset('redis-cache', 'Redis (Session Cache)');
$redisCache->type             = AssetType::Datastore;
$redisCache->technology       = Technology::Database;
$redisCache->size             = Size::Component;
$redisCache->machine          = Machine::Virtual;
$redisCache->encryption       = Encryption::Transparent;
$redisCache->confidentiality  = Confidentiality::StrictlyConfidential;
$redisCache->integrity        = Integrity::Critical;
$redisCache->availability     = Availability::Critical;
$redisCache->owner            = 'Platform Team';
$redisCache->dataAssetsStored = ['session-token'];
$model->addTechnicalAsset($redisCache);

$messageQueue = new TechnicalAsset('message-queue', 'RabbitMQ (Message Queue)');
$messageQueue->type             = AssetType::Datastore;
$messageQueue->technology       = Technology::MessageQueue;
$messageQueue->size             = Size::Component;
$messageQueue->machine          = Machine::Virtual;
$messageQueue->encryption       = Encryption::Transparent;
$messageQueue->confidentiality  = Confidentiality::Internal;
$messageQueue->integrity        = Integrity::Important;
$messageQueue->availability     = Availability::Important;
$messageQueue->owner            = 'Platform Team';
$messageQueue->dataAssetsStored = ['order-data', 'notification-payload'];
$model->addTechnicalAsset($messageQueue);

// ── Trust Boundaries ──────────────────────────────────────────────────────────

$internet = new TrustBoundary('internet', 'Public Internet', TrustBoundaryType::NetworkDedicatedHoster);
$internet->description = 'Untrusted external zone: end users and third-party payment providers';
$internet->addAssets('browser', 'payment-provider');
$model->addTrustBoundary($internet);

$dmz = new TrustBoundary('dmz', 'DMZ (Load Balancer + WAF)', TrustBoundaryType::NetworkCloudSecurityGroup);
$dmz->description = 'Public-facing tier behind a WAF; only HTTPS/443 ingress allowed';
$dmz->addAssets('web-app');
$model->addTrustBoundary($dmz);

$internalVpc = new TrustBoundary('internal-vpc', 'Internal VPC', TrustBoundaryType::NetworkCloudProvider);
$internalVpc->description = 'Private subnet; no direct internet access; mutual TLS between services';
$internalVpc->addAssets('auth-service', 'order-service', 'notification-service');
$model->addTrustBoundary($internalVpc);

$dataLayer = new TrustBoundary('data-layer', 'Data Layer', TrustBoundaryType::NetworkCloudSecurityGroup);
$dataLayer->description = 'Isolated data tier; accessible only from internal-vpc security group';
$dataLayer->addAssets('main-db', 'redis-cache', 'message-queue');
$model->addTrustBoundary($dataLayer);

return $model;

