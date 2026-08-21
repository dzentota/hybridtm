<?php

declare(strict_types=1);

namespace HybridTM\Codec;

use HybridTM\DSL\AbuseCase;
use HybridTM\DSL\CommunicationLink;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\PropertyBag;
use HybridTM\DSL\Question;
use HybridTM\DSL\RiskTracking;
use HybridTM\DSL\SecurityRequirement;
use HybridTM\DSL\SharedRuntime;
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
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\DecisionStatus;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\Size;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;
use HybridTM\Validation\Rules\KbComponentTag;

/**
 * Encodes/decodes the canonical JSON model (schema/canonical-model.v1.json,
 * T-4.1) — the contract between Studio, the API and this library, and the
 * storage format for model versions.
 *
 * The schema's `component.overrides` object is meant to hold deviations
 * from a KB component's expanded defaults (ADR-03). `ComponentExpander`
 * (T-2.10) doesn't exist yet, so there is nothing to diff against: this
 * codec puts every concrete DSL field into `overrides` unconditionally.
 * That is correct and lossless, just not yet the minimal diff the schema
 * envisions — a natural follow-up once expansion lands, not a bug here.
 *
 * `kbComponent`/`kbVersion` round-trip through the `kb-component:<id>
 * [@<version>]` tag convention already used by the T-1.8 validators
 * (`Validation\Rules\KbComponentTag`).
 *
 * Known lossy fields, all pre-existing gaps in the DSL itself rather than
 * something introduced here: `ThreatModel` has no `id` distinct from
 * `title` (the schema's `model.id` is discarded on decode); `AbuseCase`/
 * `SecurityRequirement` have `id`+`description`, not the schema's
 * `title`+`text` — `id` doubles as `title` on encode, and `title` becomes
 * the new `id` on decode (must still be a valid slug); KB component
 * `ports` (`sourcePort`/`targetPort`) and `codeRef` have no DSL
 * counterpart yet and are silently dropped/ignored.
 */
final class ModelJsonCodec
{
    private const SCHEMA_VERSION = 1;

    /** @return array<string, mixed> */
    public function encode(ThreatModel $model, string $kbVersion = ''): array
    {
        $data = [
            'schemaVersion' => self::SCHEMA_VERSION,
            'model' => array_filter([
                'title' => $model->title,
                'description' => $model->description,
                'author' => $model->author,
                'date' => $model->date !== '' ? $model->date : null,
                'businessCriticality' => $model->businessCriticality->value,
                'managementSummaryComment' => $model->managementSummaryComment,
            ], static fn ($v): bool => $v !== null && $v !== ''),
            'dataAssets' => array_values(array_map($this->encodeDataAsset(...), $model->getDataAssets())),
            'components' => array_values(array_map($this->encodeComponent(...), $model->getTechnicalAssets())),
            'trustBoundaries' => array_values(array_map($this->encodeTrustBoundary(...), $model->getTrustBoundaries())),
            'dataFlows' => $this->encodeDataFlows($model),
            'sharedRuntimes' => array_values(array_map($this->encodeSharedRuntime(...), $model->getSharedRuntimes())),
            'riskTracking' => array_values(array_map($this->encodeRiskTracking(...), $model->getRiskTracking())),
            'questions' => array_values(array_map($this->encodeQuestion(...), $model->getQuestions())),
            'abuseCases' => array_values(array_map(
                static fn (AbuseCase $c): array => ['title' => $c->id, 'text' => $c->description],
                $model->getAbuseCases(),
            )),
            'securityRequirements' => array_values(array_map(
                static fn (SecurityRequirement $r): array => ['title' => $r->id, 'text' => $r->description],
                $model->getSecurityRequirements(),
            )),
        ];

        if ($kbVersion !== '') {
            $data['kbVersion'] = $kbVersion;
        }

        return $data;
    }

    /** @param array<string, mixed> $data */
    public function decode(array $data): ThreatModel
    {
        $meta = (array) ($data['model'] ?? []);
        $model = new ThreatModel((string) ($meta['title'] ?? ''));
        $model->description = (string) ($meta['description'] ?? '');
        $model->author = (string) ($meta['author'] ?? '');
        $model->date = (string) ($meta['date'] ?? '');
        $model->businessCriticality = BusinessCriticality::tryFrom((string) ($meta['businessCriticality'] ?? ''))
            ?? BusinessCriticality::Important;
        $model->managementSummaryComment = (string) ($meta['managementSummaryComment'] ?? '');

        foreach ((array) ($data['dataAssets'] ?? []) as $raw) {
            $model->addDataAsset($this->decodeDataAsset((array) $raw));
        }
        foreach ((array) ($data['components'] ?? []) as $raw) {
            $model->addTechnicalAsset($this->decodeComponent((array) $raw));
        }
        foreach ((array) ($data['trustBoundaries'] ?? []) as $raw) {
            $model->addTrustBoundary($this->decodeTrustBoundary((array) $raw));
        }
        foreach ((array) ($data['dataFlows'] ?? []) as $raw) {
            $this->decodeDataFlow($model, (array) $raw);
        }
        foreach ((array) ($data['sharedRuntimes'] ?? []) as $raw) {
            $model->addSharedRuntime($this->decodeSharedRuntime((array) $raw));
        }
        foreach ((array) ($data['riskTracking'] ?? []) as $raw) {
            $model->addRiskTracking($this->decodeRiskTracking((array) $raw));
        }
        foreach ((array) ($data['questions'] ?? []) as $raw) {
            $raw = (array) $raw;
            $answer = (string) ($raw['answer'] ?? '');
            $model->addQuestion(new Question((string) $raw['id'], (string) $raw['text'], $answer !== '' ? $answer : null));
        }
        foreach ((array) ($data['abuseCases'] ?? []) as $raw) {
            $raw = (array) $raw;
            $model->addAbuseCase(new AbuseCase((string) $raw['title'], (string) ($raw['text'] ?? '')));
        }
        foreach ((array) ($data['securityRequirements'] ?? []) as $raw) {
            $raw = (array) $raw;
            $model->addSecurityRequirement(new SecurityRequirement((string) $raw['title'], (string) ($raw['text'] ?? '')));
        }

        return $model;
    }

    /** @return array<string, mixed> */
    private function encodeDataAsset(DataAsset $asset): array
    {
        return array_filter([
            'id' => $asset->id,
            'name' => $asset->name,
            'description' => $asset->description,
            'usage' => $asset->usage->value,
            'origin' => $asset->origin->value,
            'owner' => $asset->owner,
            'quantity' => $asset->quantity->value,
            'confidentiality' => $asset->confidentiality->value,
            'integrity' => $asset->integrity->value,
            'availability' => $asset->availability->value,
            'justificationCiaRating' => $asset->justificationCiaRating,
            'tags' => $asset->tags,
        ], static fn ($v): bool => $v !== '' && $v !== []);
    }

    /** @param array<string, mixed> $raw */
    private function decodeDataAsset(array $raw): DataAsset
    {
        $asset = new DataAsset((string) $raw['id'], (string) ($raw['name'] ?? $raw['id']));
        $asset->description = (string) ($raw['description'] ?? '');
        $asset->usage = DataUsage::tryFrom((string) ($raw['usage'] ?? '')) ?? DataUsage::Business;
        $asset->origin = DataOrigin::tryFrom((string) ($raw['origin'] ?? '')) ?? DataOrigin::Unknown;
        $asset->owner = (string) ($raw['owner'] ?? '');
        $asset->quantity = Quantity::tryFrom((string) ($raw['quantity'] ?? '')) ?? Quantity::Many;
        $asset->confidentiality = Confidentiality::tryFrom((string) ($raw['confidentiality'] ?? '')) ?? Confidentiality::Internal;
        $asset->integrity = Integrity::tryFrom((string) ($raw['integrity'] ?? '')) ?? Integrity::Operational;
        $asset->availability = Availability::tryFrom((string) ($raw['availability'] ?? '')) ?? Availability::Operational;
        $asset->justificationCiaRating = (string) ($raw['justificationCiaRating'] ?? '');
        $asset->tags = array_map(static fn ($t): string => (string) $t, (array) ($raw['tags'] ?? []));

        return $asset;
    }

    /** @return array<string, mixed> */
    private function encodeComponent(TechnicalAsset $asset): array
    {
        $kbTag = KbComponentTag::fromTags($asset->tags);

        $overrides = array_filter([
            'type' => $asset->type->value,
            'technology' => $asset->technology->value,
            'technologies' => $asset->technologies->values(),
            'machine' => $asset->machine->value,
            'size' => $asset->size->value,
            'encryption' => $asset->encryption->value,
            'confidentiality' => $asset->confidentiality->value,
            'integrity' => $asset->integrity->value,
            'availability' => $asset->availability->value,
            'usage' => $asset->usage->value,
            'internet' => $asset->internet,
            'multiTenant' => $asset->multiTenant,
            'redundant' => $asset->redundant,
            'customDevelopedParts' => $asset->customDevelopedParts,
            'usedAsClientByHuman' => $asset->usedAsClientByHuman,
            'outOfScope' => $asset->outOfScope,
            'justificationOutOfScope' => $asset->justificationOutOfScope,
            'justificationCiaRating' => $asset->justificationCiaRating,
            'owner' => $asset->owner,
        ], static fn ($v): bool => $v !== '' && $v !== [] && $v !== false);

        $tagsWithoutKbMarker = array_values(array_filter(
            $asset->tags,
            static fn (string $t): bool => !str_starts_with($t, 'kb-component:'),
        ));

        return array_filter([
            'id' => $asset->id,
            'name' => $asset->name,
            'description' => $asset->description,
            'kbComponent' => $kbTag?->componentId,
            'kbVersion' => $kbTag?->version,
            'properties' => $asset->properties->toArray(),
            'traits' => $asset->traits,
            'overrides' => $overrides,
            'dataAssetsProcessed' => $asset->dataAssetsProcessed,
            'dataAssetsStored' => $asset->dataAssetsStored,
            'dataFormatsAccepted' => $asset->dataFormatsAccepted,
            'tags' => $tagsWithoutKbMarker,
        ], static fn ($v): bool => $v !== '' && $v !== [] && $v !== null);
    }

    /** @param array<string, mixed> $raw */
    private function decodeComponent(array $raw): TechnicalAsset
    {
        $asset = new TechnicalAsset((string) $raw['id'], (string) ($raw['name'] ?? $raw['id']));
        $asset->description = (string) ($raw['description'] ?? '');
        $asset->properties = new PropertyBag($this->nonNullProperties((array) ($raw['properties'] ?? [])));
        $asset->traits = array_values(array_map(static fn ($t): string => (string) $t, (array) ($raw['traits'] ?? [])));
        $asset->dataAssetsProcessed = array_map(static fn ($v): string => (string) $v, (array) ($raw['dataAssetsProcessed'] ?? []));
        $asset->dataAssetsStored = array_map(static fn ($v): string => (string) $v, (array) ($raw['dataAssetsStored'] ?? []));
        $asset->dataFormatsAccepted = array_map(static fn ($v): string => (string) $v, (array) ($raw['dataFormatsAccepted'] ?? []));
        $asset->tags = array_map(static fn ($v): string => (string) $v, (array) ($raw['tags'] ?? []));

        if (isset($raw['kbComponent'])) {
            $marker = 'kb-component:' . $raw['kbComponent'] . (isset($raw['kbVersion']) ? '@' . $raw['kbVersion'] : '');
            $asset->tags[] = $marker;
        }

        $overrides = (array) ($raw['overrides'] ?? []);
        $asset->type = AssetType::tryFrom((string) ($overrides['type'] ?? '')) ?? AssetType::Process;
        $asset->technology = Technology::tryFrom((string) ($overrides['technology'] ?? '')) ?? Technology::WebServiceRest;
        foreach ((array) ($overrides['technologies'] ?? []) as $tech) {
            $asset->technologies->add(Technology::tryFrom((string) $tech) ?? (string) $tech);
        }
        $asset->machine = Machine::tryFrom((string) ($overrides['machine'] ?? '')) ?? Machine::Virtual;
        $asset->size = Size::tryFrom((string) ($overrides['size'] ?? '')) ?? Size::Service;
        $asset->encryption = Encryption::tryFrom((string) ($overrides['encryption'] ?? '')) ?? Encryption::None;
        $asset->confidentiality = Confidentiality::tryFrom((string) ($overrides['confidentiality'] ?? '')) ?? Confidentiality::Internal;
        $asset->integrity = Integrity::tryFrom((string) ($overrides['integrity'] ?? '')) ?? Integrity::Operational;
        $asset->availability = Availability::tryFrom((string) ($overrides['availability'] ?? '')) ?? Availability::Operational;
        $asset->usage = DataUsage::tryFrom((string) ($overrides['usage'] ?? '')) ?? DataUsage::Business;
        $asset->internet = (bool) ($overrides['internet'] ?? false);
        $asset->multiTenant = (bool) ($overrides['multiTenant'] ?? false);
        $asset->redundant = (bool) ($overrides['redundant'] ?? false);
        $asset->customDevelopedParts = (bool) ($overrides['customDevelopedParts'] ?? false);
        $asset->usedAsClientByHuman = (bool) ($overrides['usedAsClientByHuman'] ?? false);
        $asset->outOfScope = (bool) ($overrides['outOfScope'] ?? false);
        $asset->justificationOutOfScope = (string) ($overrides['justificationOutOfScope'] ?? '');
        $asset->justificationCiaRating = (string) ($overrides['justificationCiaRating'] ?? '');
        $asset->owner = (string) ($overrides['owner'] ?? '');

        return $asset;
    }

    /** @return array<string, mixed> */
    private function encodeTrustBoundary(TrustBoundary $boundary): array
    {
        return array_filter([
            'id' => $boundary->id,
            'name' => $boundary->name,
            'description' => $boundary->description,
            'type' => $boundary->type->value,
            'contains' => $boundary->technicalAssetsInside,
            'nested' => $boundary->trustBoundariesNested,
            'tags' => $boundary->tags,
        ], static fn ($v): bool => $v !== '' && $v !== []);
    }

    /** @param array<string, mixed> $raw */
    private function decodeTrustBoundary(array $raw): TrustBoundary
    {
        $boundary = new TrustBoundary(
            (string) $raw['id'],
            (string) ($raw['name'] ?? $raw['id']),
            TrustBoundaryType::tryFrom((string) ($raw['type'] ?? '')) ?? TrustBoundaryType::NetworkOnPrem,
        );
        $boundary->description = (string) ($raw['description'] ?? '');
        $boundary->technicalAssetsInside = array_map(static fn ($v): string => (string) $v, (array) ($raw['contains'] ?? []));
        $boundary->trustBoundariesNested = array_map(static fn ($v): string => (string) $v, (array) ($raw['nested'] ?? []));
        $boundary->tags = array_map(static fn ($v): string => (string) $v, (array) ($raw['tags'] ?? []));

        return $boundary;
    }

    /** @return list<array<string, mixed>> */
    private function encodeDataFlows(ThreatModel $model): array
    {
        $result = [];
        foreach ($model->getTechnicalAssets() as $sourceId => $asset) {
            foreach ($asset->communicationLinks as $link) {
                $result[] = array_filter([
                    'id' => $link->id,
                    'sourceId' => $sourceId,
                    'targetId' => $link->targetAssetId,
                    'description' => $link->description,
                    'protocol' => $link->protocol->value,
                    'authentication' => $link->authentication->value,
                    'authorization' => $link->authorization->value,
                    'usage' => $link->usage->value,
                    'vpn' => $link->vpn,
                    'ipFiltered' => $link->ipFiltered,
                    'readonly' => $link->readonly,
                    'dataSent' => $link->dataSent,
                    'dataReceived' => $link->dataReceived,
                    'properties' => $link->properties->toArray(),
                    'tags' => $link->tags,
                ], static fn ($v): bool => $v !== '' && $v !== [] && $v !== false);
            }
        }
        return $result;
    }

    /** @param array<string, mixed> $raw */
    private function decodeDataFlow(ThreatModel $model, array $raw): void
    {
        $source = $model->getTechnicalAsset((string) $raw['sourceId']);
        if ($source === null) {
            return;
        }

        $linkId = (string) ($raw['id'] ?? $raw['sourceId'] . '-to-' . $raw['targetId']);
        $link = new CommunicationLink(
            $linkId,
            (string) $raw['targetId'],
            Protocol::tryFrom((string) ($raw['protocol'] ?? '')) ?? Protocol::Https,
            Authentication::tryFrom((string) ($raw['authentication'] ?? '')) ?? Authentication::None,
            Authorization::tryFrom((string) ($raw['authorization'] ?? '')) ?? Authorization::None,
        );
        $link->description = (string) ($raw['description'] ?? '');
        $link->usage = DataUsage::tryFrom((string) ($raw['usage'] ?? '')) ?? DataUsage::Business;
        $link->vpn = (bool) ($raw['vpn'] ?? false);
        $link->ipFiltered = (bool) ($raw['ipFiltered'] ?? false);
        $link->readonly = (bool) ($raw['readonly'] ?? false);
        $link->dataSent = array_map(static fn ($v): string => (string) $v, (array) ($raw['dataSent'] ?? []));
        $link->dataReceived = array_map(static fn ($v): string => (string) $v, (array) ($raw['dataReceived'] ?? []));
        $link->properties = new PropertyBag($this->nonNullProperties((array) ($raw['properties'] ?? [])));
        $link->tags = array_map(static fn ($v): string => (string) $v, (array) ($raw['tags'] ?? []));

        $source->communicationLinks[$linkId] = $link;
    }

    /**
     * PropertyBag rejects null values (T-1.2's own tested contract) while
     * the canonical schema's propertyBag allows them — treat a null the
     * same as an absent key rather than relaxing PropertyBag's contract.
     *
     * @param array<string, mixed> $properties
     * @return array<string, mixed>
     */
    private function nonNullProperties(array $properties): array
    {
        return array_filter($properties, static fn ($v): bool => $v !== null);
    }

    /** @return array<string, mixed> */
    private function encodeSharedRuntime(SharedRuntime $runtime): array
    {
        return array_filter([
            'id' => $runtime->id,
            'name' => $runtime->name,
            'description' => $runtime->description,
            'runsOn' => $runtime->technicalAssetsRunning,
            'tags' => $runtime->tags,
        ], static fn ($v): bool => $v !== '' && $v !== []);
    }

    /** @param array<string, mixed> $raw */
    private function decodeSharedRuntime(array $raw): SharedRuntime
    {
        $runtime = new SharedRuntime((string) $raw['id'], (string) ($raw['name'] ?? $raw['id']));
        $runtime->description = (string) ($raw['description'] ?? '');
        $runtime->technicalAssetsRunning = array_map(static fn ($v): string => (string) $v, (array) ($raw['runsOn'] ?? []));
        $runtime->tags = array_map(static fn ($v): string => (string) $v, (array) ($raw['tags'] ?? []));

        return $runtime;
    }

    /** @return array<string, mixed> */
    private function encodeRiskTracking(RiskTracking $tracking): array
    {
        return array_filter([
            'findingStableId' => $tracking->syntheticRiskId,
            'status' => $tracking->status->value,
            'justification' => $tracking->justification,
            'ticket' => $tracking->ticket !== '' ? $tracking->ticket : null,
            'expiresAt' => $tracking->expiresAt,
            'decidedBy' => $tracking->checkedBy,
            'decidedAt' => $tracking->date !== '' ? $tracking->date : null,
        ], static fn ($v): bool => $v !== null && $v !== '');
    }

    /** @param array<string, mixed> $raw */
    private function decodeRiskTracking(array $raw): RiskTracking
    {
        $tracking = new RiskTracking((string) $raw['findingStableId']);
        $tracking->status = DecisionStatus::tryFrom((string) ($raw['status'] ?? '')) ?? DecisionStatus::Open;
        $tracking->justification = (string) ($raw['justification'] ?? '');
        $tracking->ticket = (string) ($raw['ticket'] ?? '');
        $tracking->expiresAt = isset($raw['expiresAt']) ? (string) $raw['expiresAt'] : null;
        $tracking->checkedBy = (string) ($raw['decidedBy'] ?? '');
        $tracking->date = (string) ($raw['decidedAt'] ?? '');

        return $tracking;
    }

    /** @return array<string, mixed> */
    private function encodeQuestion(Question $question): array
    {
        return array_filter([
            'id' => $question->id,
            'text' => $question->text,
            'answer' => $question->answer,
        ], static fn ($v): bool => $v !== null && $v !== '');
    }
}
