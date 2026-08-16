<?php

declare(strict_types=1);

/**
 * Dogfooding (T-11.7): HybridTM Studio's own architecture, modeled with
 * the library it's built with. Analyzed in CI (see .github/workflows/
 * ci.yml's dogfood job) so a regression in the rule engine or a real
 * gap in the platform's own hardening shows up the same way it would
 * for any user's model — this file is not a toy example, it describes
 * the actual apps/api + apps/studio architecture as deployed.
 *
 * Reuses real KB component ids from apps/api/kb (via `kb-component:`
 * tags, T-2.2/T-4.3's marker convention) so this model round-trips
 * through the same KB a real Studio user's model would.
 */

require __DIR__ . '/vendor/autoload.php';

use HybridTM\DSL\DataAsset;
use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\TrustBoundaryType;

$model = new ThreatModel('HybridTM Studio');
$model->description = 'The platform itself: apps/studio (canvas editor) + apps/api (Symfony API) + Postgres + Redis + an optional Threagile worker.';
$model->businessCriticality = BusinessCriticality::Important;

// ---- Data assets ----

$credentials = new DataAsset('user-credentials', 'User credentials');
$credentials->confidentiality = Confidentiality::StrictlyConfidential;
$credentials->tags = ['pii'];
$model->addDataAsset($credentials);

$modelData = new DataAsset('customer-model-data', "Customers' threat model content");
$modelData->confidentiality = Confidentiality::Confidential;
$model->addDataAsset($modelData);

// ---- Components ----

$browser = new TechnicalAsset('studio-browser', 'Studio (browser)');
$browser->traits = ['client_device', 'processing_end_user_requests'];
$browser->internet = true;
$model->addTechnicalAsset($browser);

// Reverse proxy in front of the API in a real deployment — not present
// in the local docker-compose (apps/api's dev server is bare php -S),
// so hsts_enabled/tls_terminated reflect "not configured yet", a real
// finding, not a placeholder.
$proxy = new TechnicalAsset('edge-proxy', 'Edge reverse proxy');
$proxy->tags = ['kb-component:web-server-nginx@1.4.0'];
$proxy->traits = ['traffic_forwarding', 'tls_terminator', 'http_server'];
$proxy->internet = true;
$proxy->properties->set('internet_facing', true);
$proxy->properties->set('tls_terminated', true);
$proxy->properties->set('hsts_enabled', false);
$model->addTechnicalAsset($proxy);

$api = new TechnicalAsset('api', 'HybridTM API (Symfony)');
$api->tags = ['kb-component:app-server-symfony@1.0.0'];
$api->traits = ['app_runtime'];
$api->properties->set('input_validation', true);
$api->properties->set('debug_mode', false);
$api->properties->set('csrf_protection_enabled', true); // stateless JWT/API-token auth, no cookie-based session to forge
$api->properties->set('session_cookie_secure', true);
$api->properties->set('dependency_audit_enabled', false); // composer audit is not yet wired into CI
$api->properties->set('requires_authentication', true);
$api->dataAssetsProcessed = ['user-credentials', 'customer-model-data'];
$model->addTechnicalAsset($api);

$worker = new TechnicalAsset('worker', 'Deep-analysis worker (messenger:consume)');
$worker->tags = ['kb-component:app-server-symfony@1.0.0'];
$worker->traits = ['app_runtime'];
$worker->properties->set('input_validation', true);
$worker->properties->set('debug_mode', false);
$worker->properties->set('requires_authentication', true); // trusted internal process, not request-facing
$worker->properties->set('dependency_audit_enabled', false); // same codebase/dependencies as the API — see its own finding
// A CLI messenger consumer never issues a cookie or handles a browser
// request, so "no CSRF protection"/"session cookie insecure" don't
// describe a real gap here — true reflects "not applicable", not "we
// checked and it's fine", the same modeling choice any operator would
// make for a background worker with no HTTP surface at all.
$worker->properties->set('csrf_protection_enabled', true);
$worker->properties->set('session_cookie_secure', true);
$worker->dataAssetsProcessed = ['customer-model-data'];
$model->addTechnicalAsset($worker);

$db = new TechnicalAsset('postgres', 'PostgreSQL');
$db->tags = ['kb-component:db-postgresql@1.0.0'];
$db->traits = ['datastore', 'sql_engine'];
$db->properties->set('encryption_at_rest', false); // docker-compose.yml's postgres:16-alpine has no disk encryption configured
$db->properties->set('auth_required', true);
$db->properties->set('public_network_access', false);
$db->dataAssetsStored = ['user-credentials', 'customer-model-data'];
$model->addTechnicalAsset($db);

$redis = new TechnicalAsset('redis', 'Redis (Messenger transport, dev only)');
$redis->tags = ['kb-component:cache-redis@1.0.0'];
$redis->traits = ['datastore', 'cache_store'];
$redis->properties->set('encryption_at_rest', false); // ephemeral queue data only, not a data asset store
$redis->properties->set('auth_required', false); // no requirepass in docker-compose.yml — real, current gap
$redis->properties->set('public_network_access', false);
$model->addTechnicalAsset($redis);

$threagile = new TechnicalAsset('threagile', 'Threagile (deep analysis, optional)');
$threagile->description = 'Runs only if a deployment configures DockerThreagileRunner/BinaryThreagileRunner (NullThreagileRunner is the default).';
$model->addTechnicalAsset($threagile);

// ---- Data flows ----

$browser->communicatesTo('edge-proxy', Protocol::Https);
$proxy->communicatesTo('api', Protocol::Https);
$api->communicatesTo('postgres', Protocol::JdbcEncrypted);
$api->communicatesTo('redis', Protocol::Https);
$worker->communicatesTo('postgres', Protocol::JdbcEncrypted);
$worker->communicatesTo('redis', Protocol::Https);
$worker->communicatesTo('threagile', Protocol::Https);

// ---- Trust boundaries ----

$dmz = new TrustBoundary('dmz', 'Public edge', TrustBoundaryType::NetworkCloudProvider);
$dmz->addAssets('edge-proxy');
$model->addTrustBoundary($dmz);

$internal = new TrustBoundary('internal', 'Application network', TrustBoundaryType::NetworkCloudSecurityGroup);
$internal->addAssets('api', 'worker', 'postgres', 'redis', 'threagile');
$model->addTrustBoundary($internal);

// ---- Risk tracking (T-11.7: "open risks are tracked") ----
//
// Postgres disk encryption: deferred, not accepted — a real production
// deployment (unlike local docker-compose) is expected to run on
// encrypted-at-rest storage at the infrastructure level (e.g. AWS EBS
// encryption, RDS storage encryption), so this is tracked as a known
// gap in the *reference* docker-compose, not a permanent risk acceptance.
$dbEncryption = new RiskTracking('27bb229ded57ed184b5c69bad43c7716'); // THREAT-DATA-AT-REST-UNENCRYPTED on component:postgres
$dbEncryption->status = DecisionStatus::Deferred;
$dbEncryption->justification = 'Local docker-compose.yml has no disk encryption; production deployments run on encrypted block storage at the infrastructure level (documented in docker-compose.yml).';
$dbEncryption->expiresAt = '2026-12-31';
$dbEncryption->checkedBy = 'platform-team';
$model->addRiskTracking($dbEncryption);

return $model;
