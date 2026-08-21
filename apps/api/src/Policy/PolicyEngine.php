<?php

declare(strict_types=1);

namespace App\Policy;

use HybridTM\Analysis\AnalysisResult;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Confidentiality;
use Symfony\Component\Yaml\Yaml;

/**
 * Policy-as-code (T-9.7): evaluates policy.yaml's rules against a model
 * and its analysis result, blocking a ModelVersion from reaching Approved
 * (WorkflowController) if any policy is violated. A pure function of
 * (model, result) — no side effects, same as the RuleEngine it consumes,
 * so a policy check is exactly as reproducible as the analysis it's
 * gating.
 */
final class PolicyEngine
{
    private const SEVERITY_RANK = [
        'low' => 0,
        'medium' => 1,
        'elevated' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    public function __construct(private readonly string $policyPath)
    {
    }

    /** @return list<PolicyViolation> */
    public function evaluate(ThreatModel $model, AnalysisResult $result): array
    {
        if (!is_file($this->policyPath)) {
            return [];
        }

        $config = Yaml::parseFile($this->policyPath);
        $violations = [];

        foreach ((array) ($config['policies'] ?? []) as $policy) {
            $violations = [...$violations, ...$this->evaluatePolicy($policy, $model, $result)];
        }

        return $violations;
    }

    /**
     * @param array<string, mixed> $policy
     * @return list<PolicyViolation>
     */
    private function evaluatePolicy(array $policy, ThreatModel $model, AnalysisResult $result): array
    {
        return match ($policy['type'] ?? null) {
            'max_severity' => $this->checkMaxSeverity($policy, $result),
            'required_property_for_data_tag' => $this->checkRequiredPropertyForDataTag($policy, $model),
            'required_property_for_confidentiality' => $this->checkRequiredPropertyForConfidentiality($policy, $model),
            default => [],
        };
    }

    /** @param array<string, mixed> $policy @return list<PolicyViolation> */
    private function checkMaxSeverity(array $policy, AnalysisResult $result): array
    {
        $maxRank = self::SEVERITY_RANK[(string) $policy['max_severity']] ?? self::SEVERITY_RANK['critical'];
        $violations = [];

        foreach ($result->findings as $finding) {
            $rank = self::SEVERITY_RANK[$finding->severity->value] ?? 0;
            if ($rank > $maxRank) {
                $violations[] = new PolicyViolation(
                    (string) $policy['id'],
                    (string) $policy['description'],
                    $finding->subject,
                    "Finding \"{$finding->title}\" is {$finding->severity->value}, exceeding the allowed maximum of {$policy['max_severity']}.",
                );
            }
        }

        return $violations;
    }

    /** @param array<string, mixed> $policy @return list<PolicyViolation> */
    private function checkRequiredPropertyForDataTag(array $policy, ThreatModel $model): array
    {
        $tag = (string) $policy['data_tag'];
        $property = (string) $policy['property'];
        $expected = (bool) $policy['value'];
        $violations = [];

        $taggedDataIds = [];
        foreach ($model->getDataAssets() as $id => $dataAsset) {
            if (\in_array($tag, $dataAsset->tags, true)) {
                $taggedDataIds[$id] = true;
            }
        }

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            $handlesTagged = false;
            foreach ([...$asset->dataAssetsProcessed, ...$asset->dataAssetsStored] as $dataId) {
                if (isset($taggedDataIds[$dataId])) {
                    $handlesTagged = true;
                    break;
                }
            }
            if (!$handlesTagged) {
                continue;
            }
            if ($asset->properties->bool($property) !== $expected) {
                $violations[] = new PolicyViolation(
                    (string) $policy['id'],
                    (string) $policy['description'],
                    "component:{$assetId}",
                    "{$asset->name} handles \"{$tag}\"-tagged data but property \"{$property}\" is not {$this->boolLabel($expected)}.",
                );
            }
        }

        return $violations;
    }

    /** @param array<string, mixed> $policy @return list<PolicyViolation> */
    private function checkRequiredPropertyForConfidentiality(array $policy, ThreatModel $model): array
    {
        $threshold = Confidentiality::from((string) $policy['min_confidentiality']);
        $property = (string) $policy['property'];
        $expected = (bool) $policy['value'];
        $violations = [];

        $atOrAboveIds = [];
        foreach ($model->getDataAssets() as $id => $dataAsset) {
            if ($dataAsset->confidentiality->isAtLeast($threshold)) {
                $atOrAboveIds[$id] = true;
            }
        }

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            if (!$asset->hasTrait('datastore')) {
                continue;
            }
            $handles = false;
            foreach ([...$asset->dataAssetsProcessed, ...$asset->dataAssetsStored] as $dataId) {
                if (isset($atOrAboveIds[$dataId])) {
                    $handles = true;
                    break;
                }
            }
            if (!$handles) {
                continue;
            }
            if ($asset->properties->bool($property) !== $expected) {
                $violations[] = new PolicyViolation(
                    (string) $policy['id'],
                    (string) $policy['description'],
                    "component:{$assetId}",
                    "{$asset->name} holds data at or above \"{$policy['min_confidentiality']}\" but property \"{$property}\" is not {$this->boolLabel($expected)}.",
                );
            }
        }

        return $violations;
    }

    private function boolLabel(bool $value): string
    {
        return $value ? 'true' : 'false';
    }
}
