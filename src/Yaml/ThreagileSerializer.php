<?php
declare(strict_types=1);
namespace HybridTM\Yaml;

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
            'questions' => (object)[],
            'abuse_cases' => (object)[],
            'security_requirements' => (object)[],
            'tags_available' => [],
            'data_assets' => $this->buildDataAssets($model),
            'technical_assets' => $this->buildTechnicalAssets($model),
            'trust_boundaries' => $this->buildTrustBoundaries($model),
            'shared_runtimes' => (object)[],
            'individual_risk_categories' => (object)[],
            'risk_tracking' => (object)[],
        ];

        return Yaml::dump($data, 8, 2, Yaml::DUMP_OBJECT_AS_MAP | Yaml::DUMP_EMPTY_ARRAY_AS_SEQUENCE);
    }

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
                'technology' => $asset->technology->value,
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
}
