<?php

declare(strict_types=1);

namespace HybridTM\Threagile;

/**
 * Maps all 42 of Threagile's built-in risk categories to a HybridTM threat
 * id and a merge strategy (§5.4, T-5.3). Every category Threagile ships
 * needs an entry here — otherwise a Threagile-only finding either gets
 * silently dropped or double-counted against an equivalent HybridTM rule.
 *
 * `unknownCategories()` is how a real analysis run surfaces "Threagile
 * shipped a 43rd category we don't have a strategy for yet" instead of
 * silently mishandling it — feed it the categories seen in a live
 * risks.json and act on anything it returns (CI failure, a loud log line,
 * whatever the caller's context calls for; this class only detects the gap).
 */
final class ThreagileCategoryMap
{
    /** @var array<string, array{0: string|null, 1: MergeStrategy}> */
    private const MAP = [
        'accidental-secret-leak' => ['THREAT-SECRET-LEAK-VIA-REPO', MergeStrategy::Merge],
        'code-backdooring' => ['THREAT-SUPPLY-CHAIN-BUILD-TAMPERING', MergeStrategy::Merge],
        'container-baseimage-backdooring' => ['THREAT-SUPPLY-CHAIN-BASE-IMAGE', MergeStrategy::Merge],
        'container-platform-escape' => ['THREAT-CONTAINER-ESCAPE', MergeStrategy::Merge],
        'cross-site-request-forgery' => ['THREAT-CSRF', MergeStrategy::Merge],
        'cross-site-scripting' => ['THREAT-XSS', MergeStrategy::Merge],
        'dos-risky-access-across-trust-boundary' => ['THREAT-DOS-CROSS-BOUNDARY', MergeStrategy::Merge],
        'incomplete-model' => [null, MergeStrategy::ValidationOnly],
        'ldap-injection' => ['THREAT-LDAP-INJECTION', MergeStrategy::Merge],
        'missing-authentication' => ['THREAT-MISSING-AUTHN', MergeStrategy::Merge],
        'missing-authentication-second-factor' => ['THREAT-MISSING-MFA', MergeStrategy::Merge],
        'missing-build-infrastructure' => ['THREAT-NO-BUILD-PIPELINE', MergeStrategy::ThreagileOnly],
        'missing-cloud-hardening' => ['THREAT-CLOUD-MISCONFIGURATION', MergeStrategy::Merge],
        'missing-file-validation' => ['THREAT-UNVALIDATED-FILE-UPLOAD', MergeStrategy::Merge],
        'missing-hardening' => ['THREAT-INSUFFICIENT-HARDENING', MergeStrategy::Merge],
        'missing-identity-propagation' => ['THREAT-NO-IDENTITY-PROPAGATION', MergeStrategy::Merge],
        'missing-identity-provider-isolation' => ['THREAT-IDP-NOT-ISOLATED', MergeStrategy::ThreagileOnly],
        'missing-identity-store' => ['THREAT-NO-IDENTITY-STORE', MergeStrategy::ThreagileOnly],
        'missing-network-segmentation' => ['THREAT-FLAT-NETWORK', MergeStrategy::Merge],
        'missing-vault' => ['THREAT-NO-SECRETS-MANAGEMENT', MergeStrategy::Merge],
        'missing-vault-isolation' => ['THREAT-VAULT-NOT-ISOLATED', MergeStrategy::ThreagileOnly],
        'missing-waf' => ['THREAT-NO-WAF', MergeStrategy::Merge],
        'mixed-targets-on-shared-runtime' => ['THREAT-SHARED-RUNTIME-MIXED-TRUST', MergeStrategy::ThreagileOnly],
        'path-traversal' => ['THREAT-PATH-TRAVERSAL', MergeStrategy::Merge],
        'push-instead-of-pull-deployment' => ['THREAT-PUSH-DEPLOYMENT', MergeStrategy::ThreagileOnly],
        'search-query-injection' => ['THREAT-SEARCH-INJECTION', MergeStrategy::Merge],
        'server-side-request-forgery' => ['THREAT-SSRF', MergeStrategy::Merge],
        'service-registry-poisoning' => ['THREAT-SERVICE-REGISTRY-POISONING', MergeStrategy::ThreagileOnly],
        'sql-nosql-injection' => ['THREAT-SQL-NOSQL-INJECTION', MergeStrategy::Merge],
        'unchecked-deployment' => ['THREAT-UNCHECKED-DEPLOYMENT', MergeStrategy::ThreagileOnly],
        'unencrypted-asset' => ['THREAT-DATA-AT-REST-UNENCRYPTED', MergeStrategy::Merge],
        'unencrypted-communication' => ['THREAT-MITM-CLEARTEXT-TRANSPORT', MergeStrategy::Merge],
        'unguarded-access-from-internet' => ['THREAT-UNGUARDED-INTERNET-ACCESS', MergeStrategy::Merge],
        'unguarded-direct-datastore-access' => ['THREAT-UNGUARDED-DATASTORE-EXPOSURE', MergeStrategy::Merge],
        'unnecessary-communication-link' => [null, MergeStrategy::ValidationOnly],
        'unnecessary-data-asset' => [null, MergeStrategy::ValidationOnly],
        'unnecessary-data-transfer' => ['THREAT-EXCESSIVE-DATA-TRANSFER', MergeStrategy::Merge],
        'unnecessary-technical-asset' => [null, MergeStrategy::ValidationOnly],
        'untrusted-deserialization' => ['THREAT-UNSAFE-DESERIALIZATION', MergeStrategy::Merge],
        'wrong-communication-link-content' => [null, MergeStrategy::ValidationOnly],
        'wrong-trust-boundary-content' => [null, MergeStrategy::ValidationOnly],
        'xml-external-entity' => ['THREAT-XXE', MergeStrategy::Merge],
    ];

    public function isKnown(string $category): bool
    {
        return isset(self::MAP[$category]);
    }

    public function threatIdFor(string $category): ?string
    {
        return self::MAP[$category][0] ?? null;
    }

    public function strategyFor(string $category): MergeStrategy
    {
        return self::MAP[$category][1] ?? MergeStrategy::ThreagileOnly;
    }

    /** @return list<string> all 42 known Threagile category ids */
    public function knownCategories(): array
    {
        return array_keys(self::MAP);
    }

    /**
     * @param list<string> $categories categories actually seen, e.g. in a live risks.json
     * @return list<string> any that aren't in this map
     */
    public function unknownCategories(array $categories): array
    {
        return array_values(array_filter(
            array_unique($categories),
            fn (string $c): bool => !$this->isKnown($c),
        ));
    }
}
