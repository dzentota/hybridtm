<?php

declare(strict_types=1);

namespace HybridTM\Yaml;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use Symfony\Component\Yaml\Yaml;

final class ThreagileSerializer
{
    public function serialize(ThreatModel $model): string
    {
        $data = [
            'threagile_version' => '1.0.0',
            'title' => $model->title,
            'date' => $model->date !== '' ? $model->date : date('Y-01-01'),
            'author' => ['name' => $model->author !== '' ? $model->author : 'HybridTM'],
            'management_summary_comment' => $model->managementSummaryComment,
            'business_criticality' => $model->businessCriticality->value,
            'questions' => $this->mapOrEmpty($model->getQuestions(), static fn ($q) => $q->answer ?? ''),
            'abuse_cases' => $this->mapOrEmpty($model->getAbuseCases(), static fn ($c) => $c->description),
            'security_requirements' => $this->mapOrEmpty($model->getSecurityRequirements(), static fn ($r) => $r->description),
            'tags_available' => [],
            'data_assets' => $this->buildDataAssets($model),
            'technical_assets' => $this->buildTechnicalAssets($model),
            'trust_boundaries' => $this->buildTrustBoundaries($model),
            'shared_runtimes' => $this->buildSharedRuntimes($model),
            'individual_risk_categories' => $this->buildIndividualRiskCategories($model),
            'risk_tracking' => $this->buildRiskTracking($model),
        ];

        return Yaml::dump($data, 8, 2, Yaml::DUMP_OBJECT_AS_MAP | Yaml::DUMP_EMPTY_ARRAY_AS_SEQUENCE);
    }

    /** @return array<string, array<string, mixed>> */
    private function buildDataAssets(ThreatModel $model): array
    {
        $result = [];
        foreach ($model->getDataAssets() as $id => $asset) {
            $result[$id] = [
                'id' => $asset->id,
                'description' => $asset->description,
                'usage' => $asset->usage->value,
                'tags' => $asset->tags,
                'origin' => $asset->origin->value,
                'owner' => $asset->owner,
                'quantity' => $asset->quantity->value,
                'confidentiality' => $asset->confidentiality->value,
                'integrity' => $asset->integrity->value,
                'availability' => $asset->availability->value,
                'justification_cia_rating' => $asset->justificationCiaRating,
            ];
        }
        return $result;
    }

    /** @return array<string, array<string, mixed>> */
    private function buildTechnicalAssets(ThreatModel $model): array
    {
        $result = [];
        foreach ($model->getTechnicalAssets() as $id => $asset) {
            $links = [];
            foreach ($asset->communicationLinks as $linkId => $link) {
                $links[$linkId] = [
                    'target' => $link->targetAssetId,
                    'description' => $link->description,
                    'protocol' => $link->protocol->value,
                    'authentication' => $link->authentication->value,
                    'authorization' => $link->authorization->value,
                    'tags' => $link->tags,
                    'vpn' => $link->vpn,
                    'ip_filtered' => $link->ipFiltered,
                    'readonly' => $link->readonly,
                    'usage' => $link->usage->value,
                    'data_assets_sent' => $link->dataSent,
                    'data_assets_received' => $link->dataReceived,
                ];
            }

            $result[$id] = [
                'id' => $asset->id,
                'description' => $asset->description,
                'type' => $asset->type->value,
                'usage' => $asset->usage->value,
                'used_as_client_by_human' => $asset->usedAsClientByHuman,
                'out_of_scope' => $asset->outOfScope,
                'justification_out_of_scope' => $asset->justificationOutOfScope,
                'size' => $asset->size->value,
                ...$this->buildTechnology($asset),
                'tags' => $asset->tags,
                'internet' => $asset->internet,
                'machine' => $asset->machine->value,
                'encryption' => $asset->encryption->value,
                'owner' => $asset->owner,
                'confidentiality' => $asset->confidentiality->value,
                'integrity' => $asset->integrity->value,
                'availability' => $asset->availability->value,
                'justification_cia_rating' => $asset->justificationCiaRating,
                'multi_tenant' => $asset->multiTenant,
                'redundant' => $asset->redundant,
                'custom_developed_parts' => $asset->customDevelopedParts,
                'data_assets_processed' => array_values(array_unique($asset->dataAssetsProcessed)),
                'data_assets_stored' => array_values(array_unique($asset->dataAssetsStored)),
                'data_formats_accepted' => $asset->dataFormatsAccepted,
                // Must be a YAML map, never a sequence — use stdClass when empty.
                'communication_links' => $links !== [] ? $links : (object) [],
            ];
        }
        return $result;
    }

    /**
     * ADR-10: a multi-value `technologies:` list is emitted only once the
     * asset actually declares more than one — a single-item list still
     * degrades to the legacy `technology:` scalar, so existing models
     * (which never touch `$technologies`) produce byte-identical YAML.
     *
     * @return array{technology: string}|array{technologies: list<string>}
     */
    private function buildTechnology(TechnicalAsset $asset): array
    {
        if ($asset->technologies->count() > 1) {
            return ['technologies' => $asset->technologies->values()];
        }
        return ['technology' => $asset->technology->value];
    }

    /** @return array<string, array<string, mixed>> */
    private function buildTrustBoundaries(ThreatModel $model): array
    {
        $result = [];
        foreach ($model->getTrustBoundaries() as $id => $boundary) {
            $result[$id] = [
                'id' => $boundary->id,
                'description' => $boundary->description,
                'type' => $boundary->type->value,
                'tags' => $boundary->tags,
                'technical_assets_inside' => $boundary->technicalAssetsInside,
                'trust_boundaries_nested' => $boundary->trustBoundariesNested,
            ];
        }
        return $result;
    }

    /** @return array<string, array<string, mixed>>|\stdClass */
    private function buildSharedRuntimes(ThreatModel $model): array|\stdClass
    {
        $result = [];
        foreach ($model->getSharedRuntimes() as $id => $runtime) {
            $result[$id] = [
                'id' => $runtime->id,
                'description' => $runtime->description,
                'tags' => $runtime->tags,
                'technical_assets_running' => $runtime->technicalAssetsRunning,
            ];
        }
        return $result !== [] ? $result : (object) [];
    }

    /** @return array<string, array<string, mixed>>|\stdClass */
    private function buildIndividualRiskCategories(ThreatModel $model): array|\stdClass
    {
        $result = [];
        foreach ($model->getIndividualRiskCategories() as $id => $category) {
            $result[$id] = [
                'id' => $category->id,
                'title' => $category->title,
                'description' => $category->description,
                'impact' => $category->impact,
                'asvs' => $category->asvs,
                'cheat_sheet' => $category->cheatSheet,
                'action' => $category->action,
                'mitigation' => $category->mitigation,
                'check' => $category->check,
                'detection_logic' => $category->detectionLogic,
                'risk_assessment' => $category->riskAssessment,
                'false_positives' => $category->falsePositives,
                'function' => $category->function->value,
                'stride' => array_map(static fn ($s) => $s->value, $category->stride),
                'cwe' => $category->cwe,
            ];
        }
        return $result !== [] ? $result : (object) [];
    }

    /** @return array<string, array<string, mixed>>|\stdClass */
    private function buildRiskTracking(ThreatModel $model): array|\stdClass
    {
        $result = [];
        foreach ($model->getRiskTracking() as $syntheticRiskId => $tracking) {
            $result[$syntheticRiskId] = [
                'status' => $tracking->status->value,
                'justification' => $tracking->justification,
                'ticket' => $tracking->ticket,
                'date' => $tracking->date,
                'checked_by' => $tracking->checkedBy,
            ];
        }
        return $result !== [] ? $result : (object) [];
    }

    /**
     * @template T of object
     * @param array<string, T> $items
     * @param callable(T): string $value
     * @return array<string, string>|\stdClass
     */
    private function mapOrEmpty(array $items, callable $value): array|\stdClass
    {
        if ($items === []) {
            return (object) [];
        }

        $result = [];
        foreach ($items as $id => $item) {
            $result[$id] = $value($item);
        }
        return $result;
    }
}
