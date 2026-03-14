<?php
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

$model = new ThreatModel('User Management Service');
$model->description = 'Threat model for user registration & authentication flows.';
$model->author = 'Security Team';
$model->date = '2024-01-15';
$model->businessCriticality = BusinessCriticality::Critical;

// ── Data Assets ──────────────────────────────────────────────────────────────

$userCredentials = new DataAsset('user-credentials', 'User Credentials');
$userCredentials->description = 'Hashed passwords and authentication tokens';
$userCredentials->confidentiality = Confidentiality::StrictlyConfidential;
$userCredentials->integrity = Integrity::Critical;
$userCredentials->availability = Availability::Critical;
$userCredentials->origin = DataOrigin::UserInput;
$userCredentials->quantity = Quantity::Many;
$model->addDataAsset($userCredentials);

$userProfile = new DataAsset('user-profile', 'User Profile Data');
$userProfile->description = 'PII: name, email, address';
$userProfile->confidentiality = Confidentiality::Confidential;
$userProfile->integrity = Integrity::Important;
$userProfile->availability = Availability::Important;
$userProfile->origin = DataOrigin::UserInput;
$userProfile->quantity = Quantity::Many;
$model->addDataAsset($userProfile);

$sessionToken = new DataAsset('session-token', 'Session Token');
$sessionToken->description = 'JWT or opaque session identifier';
$sessionToken->confidentiality = Confidentiality::StrictlyConfidential;
$sessionToken->integrity = Integrity::Critical;
$sessionToken->availability = Availability::Operational;
$sessionToken->origin = DataOrigin::InHouse;
$sessionToken->quantity = Quantity::VeryMany;
$model->addDataAsset($sessionToken);

// ── Technical Assets ─────────────────────────────────────────────────────────

$browser = new TechnicalAsset('browser', 'User Browser');
$browser->type = AssetType::ExternalEntity;
$browser->technology = Technology::Browser;
$browser->size = Size::Component;
$browser->usedAsClientByHuman = true;
$browser->internet = true;
$browser->machine = Machine::Physical;
$browser->confidentiality = Confidentiality::Internal;
$browser->integrity = Integrity::Operational;
$browser->availability = Availability::Operational;
$model->addTechnicalAsset($browser);

$webApp = new TechnicalAsset('web-app', 'PHP Web Application');
$webApp->type = AssetType::Process;
$webApp->technology = Technology::WebApplication;
$webApp->size = Size::Service;
$webApp->machine = Machine::Container;
$webApp->customDevelopedParts = true;
$webApp->confidentiality = Confidentiality::Confidential;
$webApp->integrity = Integrity::Critical;
$webApp->availability = Availability::Critical;
$webApp->owner = 'Platform Team';
$model->addTechnicalAsset($webApp);

$authService = new TechnicalAsset('auth-service', 'Auth Micro-service');
$authService->type = AssetType::Process;
$authService->technology = Technology::WebServiceRest;
$authService->size = Size::Service;
$authService->machine = Machine::Container;
$authService->customDevelopedParts = true;
$authService->confidentiality = Confidentiality::Confidential;
$authService->integrity = Integrity::MissionCritical;
$authService->availability = Availability::Critical;
$authService->owner = 'Security Team';
$authService->dataAssetsProcessed = ['user-credentials', 'session-token'];
$model->addTechnicalAsset($authService);

$userDb = new TechnicalAsset('user-db', 'User Database');
$userDb->type = AssetType::Datastore;
$userDb->technology = Technology::Database;
$userDb->size = Size::Service;
$userDb->machine = Machine::Virtual;
$userDb->encryption = Encryption::DataWithSymmetricSharedKey;
$userDb->confidentiality = Confidentiality::StrictlyConfidential;
$userDb->integrity = Integrity::Critical;
$userDb->availability = Availability::Critical;
$userDb->owner = 'Platform Team';
$userDb->dataAssetsStored = ['user-credentials', 'user-profile'];
$model->addTechnicalAsset($userDb);

// ── Communication Links ──────────────────────────────────────────────────────

$browserToWeb = $browser->communicatesTo('web-app', Protocol::Https, Authentication::None, Authorization::None, 'HTTPS browser request');
$browserToWeb->dataSent = ['user-credentials'];
$browserToWeb->dataReceived = ['session-token'];

$webToAuth = $webApp->communicatesTo('auth-service', Protocol::Https, Authentication::Token, Authorization::TechnicalUser, 'Token validation');
$webToAuth->dataSent = ['user-credentials'];
$webToAuth->dataReceived = ['session-token'];

$webToDb = $webApp->communicatesTo('user-db', Protocol::JdbcEncrypted, Authentication::Credentials, Authorization::TechnicalUser, 'SQL queries');
$webToDb->dataSent = ['user-profile'];
$webToDb->dataReceived = ['user-profile', 'user-credentials'];

$authToDb = $authService->communicatesTo('user-db', Protocol::JdbcEncrypted, Authentication::Credentials, Authorization::TechnicalUser, 'Credential lookup');
$authToDb->dataSent = [];
$authToDb->dataReceived = ['user-credentials'];

// ── Trust Boundaries ─────────────────────────────────────────────────────────

$publicInternet = new TrustBoundary('public-internet', 'Public Internet', TrustBoundaryType::NetworkDedicatedHoster);
$publicInternet->description = 'Untrusted external zone';
$publicInternet->addAssets('browser');
$model->addTrustBoundary($publicInternet);

$vpcNetwork = new TrustBoundary('vpc', 'VPC / Private Network', TrustBoundaryType::NetworkCloudProvider);
$vpcNetwork->description = 'Trusted internal cloud network';
$vpcNetwork->addAssets('web-app', 'auth-service', 'user-db');
$model->addTrustBoundary($vpcNetwork);

return $model;
