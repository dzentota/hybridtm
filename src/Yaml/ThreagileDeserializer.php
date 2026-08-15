<?php
declare(strict_types=1);
namespace HybridTM\Yaml;

use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\CommunicationLink;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\IndividualRiskCategory;
use HybridTM\DSL\Question;
use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\SecurityRequirement;
use HybridTM\DSL\SharedRuntime;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\AssetType;
use HybridTM\Enums\Availability;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\RiskFunction;
use HybridTM\Enums\Size;
use HybridTM\Enums\Stride;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;
use Symfony\Component\Yaml\Yaml;

/**
 * Mirror of `ThreagileSerializer`: reads Threagile YAML back into a
 * `ThreatModel` (T-1.9). Needed for two things: migrating a team that
 * already hand-writes Threagile YAML, and round-trip tests
 * (`deserialize(serialize($m)) == $m`).
 *
 * The round-trip is exact only for what Threagile YAML can actually carry.
 * `PropertyBag` (§3.2), asset `traits` (§3.3) and a multi-value
 * `TechnologyList` (ADR-10, once it holds more than one entry) are
 * HybridTM-only extensions with no YAML representation — they are lost on
 * a `serialize()` and so cannot come back on `deserialize()`. That is by
 * design (T-1.2's own DoD is that properties never reach Threagile YAML),
 * not a bug in this class.
 *
 * A few more asymmetries to know about, all pre-existing in
 * `ThreagileSerializer` rather than introduced here:
 *  - `ThreatModel::$description` and every entity's `$name` (distinct from
 *    `$id`) are never written to YAML at all — Threagile's own schema has
 *    no top-level `description` or per-entity display name, only
 *    `management_summary_comment` and `id`. Round-trip fixtures that set
 *    either will not get them back.
 *  - `ThreagileSerializer` fills in `date('Y-01-01')` when `$date` is empty
 *    and `'HybridTM'` when `$author` is empty, and this class has no way to
 *    tell "was empty" apart from "was actually this value" on the way back
 *    — round-trip fixtures should set both explicitly.
 */
final class ThreagileDeserializer
{
    public function deserialize(string $yaml): ThreatModel
    {
        /** @var array<string, mixed> $data */
        $data = Yaml::parse($yaml) ?? [];

        $model = new ThreatModel((string) ($data['title'] ?? ''));
        $model->description = (string) ($data['description'] ?? '');
        $author = $data['author'] ?? null;
        $model->author = is_array($author) ? (string) ($author['name'] ?? '') : (string) ($author ?? '');
        $model->date = (string) ($data['date'] ?? '');
        $model->businessCriticality = BusinessCriticality::tryFrom((string) ($data['business_criticality'] ?? ''))
            ?? BusinessCriticality::Important;
        $model->managementSummaryComment = (string) ($data['management_summary_comment'] ?? '');

        foreach ($this->asMap($data['data_assets'] ?? []) as $id => $raw) {
            $model->addDataAsset($this->readDataAsset((string) $id, $raw));
        }

        foreach ($this->asMap($data['technical_assets'] ?? []) as $id => $raw) {
            $model->addTechnicalAsset($this->readTechnicalAsset((string) $id, $raw));
        }

        foreach ($this->asMap($data['trust_boundaries'] ?? []) as $id => $raw) {
            $model->addTrustBoundary($this->readTrustBoundary((string) $id, $raw));
        }

        foreach ($this->asMap($data['questions'] ?? []) as $id => $answer) {
            $model->addQuestion(new Question((string) $id, '', $answer !== '' ? (string) $answer : null));
        }

        foreach ($this->asMap($data['abuse_cases'] ?? []) as $id => $description) {
            $model->addAbuseCase(new AbuseCase((string) $id, (string) $description));
        }

        foreach ($this->asMap($data['security_requirements'] ?? []) as $id => $description) {
            $model->addSecurityRequirement(new SecurityRequirement((string) $id, (string) $description));
        }

        foreach ($this->asMap($data['shared_runtimes'] ?? []) as $id => $raw) {
            $model->addSharedRuntime($this->readSharedRuntime((string) $id, $raw));
        }

        foreach ($this->asMap($data['individual_risk_categories'] ?? []) as $id => $raw) {
            $model->addIndividualRiskCategory($this->readIndividualRiskCategory((string) $id, $raw));
        }

        foreach ($this->asMap($data['risk_tracking'] ?? []) as $id => $raw) {
            $model->addRiskTracking($this->readRiskTracking((string) $id, $raw));
        }

        return $model;
    }

    /** @param array<string, mixed> $raw */
    private function readDataAsset(string $id, array $raw): DataAsset
    {
        $asset = new DataAsset($id, $id);
        $asset->description = (string) ($raw['description'] ?? '');
        $asset->usage = DataUsage::tryFrom((string) ($raw['usage'] ?? '')) ?? DataUsage::Business;
        $asset->origin = DataOrigin::tryFrom((string) ($raw['origin'] ?? '')) ?? DataOrigin::Unknown;
        $asset->owner = (string) ($raw['owner'] ?? '');
        $asset->quantity = Quantity::tryFrom((string) ($raw['quantity'] ?? '')) ?? Quantity::Many;
        $asset->confidentiality = Confidentiality::tryFrom((string) ($raw['confidentiality'] ?? '')) ?? Confidentiality::Internal;
        $asset->integrity = Integrity::tryFrom((string) ($raw['integrity'] ?? '')) ?? Integrity::Operational;
        $asset->availability = Availability::tryFrom((string) ($raw['availability'] ?? '')) ?? Availability::Operational;
        $asset->justificationCiaRating = (string) ($raw['justification_cia_rating'] ?? '');
        $asset->tags = $this->asList($raw['tags'] ?? []);

        return $asset;
    }

    /** @param array<string, mixed> $raw */
    private function readTechnicalAsset(string $id, array $raw): TechnicalAsset
    {
        $asset = new TechnicalAsset($id, $id);
        $asset->description = (string) ($raw['description'] ?? '');
        $asset->type = AssetType::tryFrom((string) ($raw['type'] ?? '')) ?? AssetType::Process;
        $asset->usage = DataUsage::tryFrom((string) ($raw['usage'] ?? '')) ?? DataUsage::Business;
        $asset->usedAsClientByHuman = (bool) ($raw['used_as_client_by_human'] ?? false);
        $asset->outOfScope = (bool) ($raw['out_of_scope'] ?? false);
        $asset->justificationOutOfScope = (string) ($raw['justification_out_of_scope'] ?? '');
        $asset->size = Size::tryFrom((string) ($raw['size'] ?? '')) ?? Size::Service;

        if (isset($raw['technologies']) && is_array($raw['technologies'])) {
            foreach ($raw['technologies'] as $value) {
                $asset->technologies->add(Technology::tryFrom((string) $value) ?? (string) $value);
            }
        } else {
            $asset->technology = Technology::tryFrom((string) ($raw['technology'] ?? '')) ?? Technology::WebServiceRest;
        }

        $asset->tags = $this->asList($raw['tags'] ?? []);
        $asset->internet = (bool) ($raw['internet'] ?? false);
        $asset->machine = Machine::tryFrom((string) ($raw['machine'] ?? '')) ?? Machine::Virtual;
        $asset->encryption = Encryption::tryFrom((string) ($raw['encryption'] ?? '')) ?? Encryption::None;
        $asset->owner = (string) ($raw['owner'] ?? '');
        $asset->confidentiality = Confidentiality::tryFrom((string) ($raw['confidentiality'] ?? '')) ?? Confidentiality::Internal;
        $asset->integrity = Integrity::tryFrom((string) ($raw['integrity'] ?? '')) ?? Integrity::Operational;
        $asset->availability = Availability::tryFrom((string) ($raw['availability'] ?? '')) ?? Availability::Operational;
        $asset->justificationCiaRating = (string) ($raw['justification_cia_rating'] ?? '');
        $asset->multiTenant = (bool) ($raw['multi_tenant'] ?? false);
        $asset->redundant = (bool) ($raw['redundant'] ?? false);
        $asset->customDevelopedParts = (bool) ($raw['custom_developed_parts'] ?? false);
        $asset->dataAssetsProcessed = $this->asList($raw['data_assets_processed'] ?? []);
        $asset->dataAssetsStored = $this->asList($raw['data_assets_stored'] ?? []);
        $asset->dataFormatsAccepted = $this->asList($raw['data_formats_accepted'] ?? []);

        foreach ($this->asMap($raw['communication_links'] ?? []) as $linkId => $linkRaw) {
            $asset->communicationLinks[(string) $linkId] = $this->readCommunicationLink((string) $linkId, $linkRaw);
        }

        return $asset;
    }

    /** @param array<string, mixed> $raw */
    private function readCommunicationLink(string $id, array $raw): CommunicationLink
    {
        $link = new CommunicationLink(
            $id,
            (string) ($raw['target'] ?? ''),
            Protocol::tryFrom((string) ($raw['protocol'] ?? '')) ?? Protocol::Https,
            Authentication::tryFrom((string) ($raw['authentication'] ?? '')) ?? Authentication::None,
            Authorization::tryFrom((string) ($raw['authorization'] ?? '')) ?? Authorization::None,
        );
        $link->description = (string) ($raw['description'] ?? '');
        $link->tags = $this->asList($raw['tags'] ?? []);
        $link->vpn = (bool) ($raw['vpn'] ?? false);
        $link->ipFiltered = (bool) ($raw['ip_filtered'] ?? false);
        $link->readonly = (bool) ($raw['readonly'] ?? false);
        $link->usage = DataUsage::tryFrom((string) ($raw['usage'] ?? '')) ?? DataUsage::Business;
        $link->dataSent = $this->asList($raw['data_assets_sent'] ?? []);
        $link->dataReceived = $this->asList($raw['data_assets_received'] ?? []);

        return $link;
    }

    /** @param array<string, mixed> $raw */
    private function readTrustBoundary(string $id, array $raw): TrustBoundary
    {
        $boundary = new TrustBoundary(
            $id,
            $id,
            TrustBoundaryType::tryFrom((string) ($raw['type'] ?? '')) ?? TrustBoundaryType::NetworkOnPrem,
        );
        $boundary->description = (string) ($raw['description'] ?? '');
        $boundary->tags = $this->asList($raw['tags'] ?? []);
        $boundary->technicalAssetsInside = $this->asList($raw['technical_assets_inside'] ?? []);
        $boundary->trustBoundariesNested = $this->asList($raw['trust_boundaries_nested'] ?? []);

        return $boundary;
    }

    /** @param array<string, mixed> $raw */
    private function readSharedRuntime(string $id, array $raw): SharedRuntime
    {
        $runtime = new SharedRuntime($id, $id);
        $runtime->description = (string) ($raw['description'] ?? '');
        $runtime->tags = $this->asList($raw['tags'] ?? []);
        $runtime->technicalAssetsRunning = $this->asList($raw['technical_assets_running'] ?? []);

        return $runtime;
    }

    /** @param array<string, mixed> $raw */
    private function readIndividualRiskCategory(string $id, array $raw): IndividualRiskCategory
    {
        $category = new IndividualRiskCategory($id);
        $category->title = (string) ($raw['title'] ?? '');
        $category->description = (string) ($raw['description'] ?? '');
        $category->impact = (string) ($raw['impact'] ?? '');
        $category->asvs = (string) ($raw['asvs'] ?? '');
        $category->cheatSheet = (string) ($raw['cheat_sheet'] ?? '');
        $category->action = (string) ($raw['action'] ?? '');
        $category->mitigation = (string) ($raw['mitigation'] ?? '');
        $category->check = (string) ($raw['check'] ?? '');
        $category->detectionLogic = (string) ($raw['detection_logic'] ?? '');
        $category->riskAssessment = (string) ($raw['risk_assessment'] ?? '');
        $category->falsePositives = (string) ($raw['false_positives'] ?? '');
        $category->function = RiskFunction::tryFrom((string) ($raw['function'] ?? '')) ?? RiskFunction::Operations;
        $category->stride = array_values(array_filter(array_map(
            static fn ($value): ?Stride => Stride::tryFrom((string) $value),
            $this->asList($raw['stride'] ?? []),
        )));
        $category->cwe = $this->asList($raw['cwe'] ?? []);

        return $category;
    }

    /** @param array<string, mixed> $raw */
    private function readRiskTracking(string $id, array $raw): RiskTracking
    {
        $tracking = new RiskTracking($id);
        $tracking->status = DecisionStatus::tryFrom((string) ($raw['status'] ?? '')) ?? DecisionStatus::Open;
        $tracking->justification = (string) ($raw['justification'] ?? '');
        $tracking->ticket = (string) ($raw['ticket'] ?? '');
        $tracking->date = (string) ($raw['date'] ?? '');
        $tracking->checkedBy = (string) ($raw['checked_by'] ?? '');

        return $tracking;
    }

    /** @return array<string, mixed> */
    private function asMap(mixed $value): array
    {
        return is_array($value) ? $value : [];
    }

    /** @return list<string> */
    private function asList(mixed $value): array
    {
        return is_array($value) ? array_values(array_map(static fn ($v): string => (string) $v, $value)) : [];
    }
}
