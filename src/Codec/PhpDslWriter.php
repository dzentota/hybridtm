<?php
declare(strict_types=1);
namespace HybridTM\Codec;

use HybridTM\DSL\CommunicationLink;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;

/**
 * Generates a `threat-model.php` file from a `ThreatModel` (T-4.2),
 * extracted from `InitCommand::generatePhp()` — that method built its PHP
 * source from the wizard's own ad-hoc answer arrays; this one takes a real
 * `ThreatModel` so it can round-trip with `PhpDslReader` (T-4.3).
 *
 * Deterministic and idempotent by construction: no clock/random input (the
 * wizard's version stamped `date('Y-m-d')` into every file; this one only
 * writes `$model->date` if the model actually has one), and iteration order
 * follows each `ThreatModel` collection's own insertion order — the same
 * model always produces byte-identical output, and re-writing a model just
 * read back by `PhpDslReader` reproduces the same bytes again
 * (`write(read(write(m))) === write(m)`, T-4.4).
 *
 * Only emits what ADR-08's "recognizable subset" defines, since that's
 * exactly what `PhpDslReader` can parse back: `ThreatModel`, `DataAsset`,
 * `TechnicalAsset`, `TrustBoundary`, scalar/enum property assignments,
 * literal-array property assignments, `->communicatesTo(...)`, and the
 * `add*()` calls. `PropertyBag` (`->properties`), the multi-value
 * `TechnologyList` (`->technologies`), and every T-1.1 governance entity
 * (`Question`, `AbuseCase`, `SecurityRequirement`, `SharedRuntime`,
 * `IndividualRiskCategory`, `RiskTracking`) are all outside that subset —
 * PHP-DSL round-tripping for those is a distinct, separately-scoped
 * follow-up, not a bug in this class.
 */
final class PhpDslWriter
{
    public function write(ThreatModel $model): string
    {
        $lines = [];
        $lines[] = '<?php';
        $lines[] = 'declare(strict_types=1);';
        $lines[] = '';
        $lines[] = 'use HybridTM\\DSL\\DataAsset;';
        $lines[] = 'use HybridTM\\DSL\\TechnicalAsset;';
        $lines[] = 'use HybridTM\\DSL\\ThreatModel;';
        $lines[] = 'use HybridTM\\DSL\\TrustBoundary;';
        foreach ($this->collectUsedEnums($model) as $enum) {
            $lines[] = "use HybridTM\\Enums\\{$enum};";
        }
        $lines[] = '';

        $names = new VariableNamer();

        $lines[] = "\$model = new ThreatModel('" . $this->esc($model->title) . "');";
        if ($model->description !== '') {
            $lines[] = "\$model->description = '" . $this->esc($model->description) . "';";
        }
        if ($model->author !== '') {
            $lines[] = "\$model->author = '" . $this->esc($model->author) . "';";
        }
        if ($model->date !== '') {
            $lines[] = "\$model->date = '" . $this->esc($model->date) . "';";
        }
        $lines[] = "\$model->businessCriticality = BusinessCriticality::{$model->businessCriticality->name};";
        if ($model->managementSummaryComment !== '') {
            $lines[] = "\$model->managementSummaryComment = '" . $this->esc($model->managementSummaryComment) . "';";
        }
        $lines[] = '';

        foreach ($model->getDataAssets() as $id => $asset) {
            $lines = [...$lines, ...$this->writeDataAsset($asset, $names->for($id)), ''];
        }

        foreach ($model->getTechnicalAssets() as $id => $asset) {
            $lines = [...$lines, ...$this->writeTechnicalAsset($asset, $names->for($id)), ''];
        }

        foreach ($model->getTrustBoundaries() as $id => $boundary) {
            $lines = [...$lines, ...$this->writeTrustBoundary($boundary, $names->for($id)), ''];
        }

        $lines[] = 'return $model;';
        $lines[] = '';

        return implode("\n", $lines);
    }

    /** @return list<string> */
    private function writeDataAsset(DataAsset $asset, string $var): array
    {
        $lines = [];
        $lines[] = "\${$var} = new DataAsset('{$asset->id}', '" . $this->esc($asset->name) . "');";
        if ($asset->description !== '') {
            $lines[] = "\${$var}->description = '" . $this->esc($asset->description) . "';";
        }
        $lines[] = "\${$var}->usage = DataUsage::{$asset->usage->name};";
        $lines[] = "\${$var}->origin = DataOrigin::{$asset->origin->name};";
        if ($asset->owner !== '') {
            $lines[] = "\${$var}->owner = '" . $this->esc($asset->owner) . "';";
        }
        $lines[] = "\${$var}->quantity = Quantity::{$asset->quantity->name};";
        $lines[] = "\${$var}->confidentiality = Confidentiality::{$asset->confidentiality->name};";
        $lines[] = "\${$var}->integrity = Integrity::{$asset->integrity->name};";
        $lines[] = "\${$var}->availability = Availability::{$asset->availability->name};";
        if ($asset->justificationCiaRating !== '') {
            $lines[] = "\${$var}->justificationCiaRating = '" . $this->esc($asset->justificationCiaRating) . "';";
        }
        if ($asset->tags !== []) {
            $lines[] = "\${$var}->tags = " . $this->literalArray($asset->tags) . ';';
        }
        $lines[] = "\$model->addDataAsset(\${$var});";

        return $lines;
    }

    /** @return list<string> */
    private function writeTechnicalAsset(TechnicalAsset $asset, string $var): array
    {
        $lines = [];
        $lines[] = "\${$var} = new TechnicalAsset('{$asset->id}', '" . $this->esc($asset->name) . "');";
        if ($asset->description !== '') {
            $lines[] = "\${$var}->description = '" . $this->esc($asset->description) . "';";
        }
        $lines[] = "\${$var}->type = AssetType::{$asset->type->name};";
        $lines[] = "\${$var}->usage = DataUsage::{$asset->usage->name};";
        $lines[] = "\${$var}->usedAsClientByHuman = " . $this->literalBool($asset->usedAsClientByHuman) . ';';
        $lines[] = "\${$var}->outOfScope = " . $this->literalBool($asset->outOfScope) . ';';
        if ($asset->justificationOutOfScope !== '') {
            $lines[] = "\${$var}->justificationOutOfScope = '" . $this->esc($asset->justificationOutOfScope) . "';";
        }
        $lines[] = "\${$var}->size = Size::{$asset->size->name};";
        $lines[] = "\${$var}->technology = Technology::{$asset->technology->name};";
        $lines[] = "\${$var}->internet = " . $this->literalBool($asset->internet) . ';';
        $lines[] = "\${$var}->machine = Machine::{$asset->machine->name};";
        $lines[] = "\${$var}->encryption = Encryption::{$asset->encryption->name};";
        if ($asset->owner !== '') {
            $lines[] = "\${$var}->owner = '" . $this->esc($asset->owner) . "';";
        }
        $lines[] = "\${$var}->confidentiality = Confidentiality::{$asset->confidentiality->name};";
        $lines[] = "\${$var}->integrity = Integrity::{$asset->integrity->name};";
        $lines[] = "\${$var}->availability = Availability::{$asset->availability->name};";
        if ($asset->justificationCiaRating !== '') {
            $lines[] = "\${$var}->justificationCiaRating = '" . $this->esc($asset->justificationCiaRating) . "';";
        }
        $lines[] = "\${$var}->multiTenant = " . $this->literalBool($asset->multiTenant) . ';';
        $lines[] = "\${$var}->redundant = " . $this->literalBool($asset->redundant) . ';';
        $lines[] = "\${$var}->customDevelopedParts = " . $this->literalBool($asset->customDevelopedParts) . ';';
        if ($asset->dataAssetsProcessed !== []) {
            $lines[] = "\${$var}->dataAssetsProcessed = " . $this->literalArray($asset->dataAssetsProcessed) . ';';
        }
        if ($asset->dataAssetsStored !== []) {
            $lines[] = "\${$var}->dataAssetsStored = " . $this->literalArray($asset->dataAssetsStored) . ';';
        }
        if ($asset->dataFormatsAccepted !== []) {
            $lines[] = "\${$var}->dataFormatsAccepted = " . $this->literalArray($asset->dataFormatsAccepted) . ';';
        }
        if ($asset->tags !== []) {
            $lines[] = "\${$var}->tags = " . $this->literalArray($asset->tags) . ';';
        }
        if ($asset->traits !== []) {
            $lines[] = "\${$var}->traits = " . $this->literalArray($asset->traits) . ';';
        }

        foreach ($asset->communicationLinks as $link) {
            $lines = [...$lines, ...$this->writeCommunicationLink($asset, $link, $var)];
        }

        $lines[] = "\$model->addTechnicalAsset(\${$var});";

        return $lines;
    }

    /** @return list<string> */
    private function writeCommunicationLink(TechnicalAsset $source, CommunicationLink $link, string $var): array
    {
        // usage/vpn/ipFiltered/readonly/dataSent/dataReceived/tags aren't
        // communicatesTo() constructor arguments — capture its return value
        // in a variable and assign them afterward, still within ADR-08's
        // subset (scalar/enum/literal-array property assignment).
        $needsCapture = $link->dataSent !== [] || $link->dataReceived !== []
            || $link->vpn || $link->ipFiltered || $link->readonly || $link->tags !== []
            || $link->usage->value !== 'business';

        $linkVar = $var . ucfirst($this->camel($link->targetAssetId)) . 'Link';
        $callOpener = $needsCapture ? "\${$linkVar} = \${$var}->communicatesTo(" : "\${$var}->communicatesTo(";

        $lines = [$callOpener];
        $lines[] = "    targetId: '{$link->targetAssetId}',";
        $lines[] = "    protocol: Protocol::{$link->protocol->name},";
        $lines[] = "    authentication: Authentication::{$link->authentication->name},";
        $lines[] = "    authorization: Authorization::{$link->authorization->name},";
        if ($link->description !== '') {
            $lines[] = "    description: '" . $this->esc($link->description) . "',";
        }
        $lines[] = ');';

        if ($needsCapture) {
            if ($link->usage->value !== 'business') {
                $lines[] = "\${$linkVar}->usage = DataUsage::{$link->usage->name};";
            }
            if ($link->vpn) {
                $lines[] = "\${$linkVar}->vpn = true;";
            }
            if ($link->ipFiltered) {
                $lines[] = "\${$linkVar}->ipFiltered = true;";
            }
            if ($link->readonly) {
                $lines[] = "\${$linkVar}->readonly = true;";
            }
            if ($link->dataSent !== []) {
                $lines[] = "\${$linkVar}->dataSent = " . $this->literalArray($link->dataSent) . ';';
            }
            if ($link->dataReceived !== []) {
                $lines[] = "\${$linkVar}->dataReceived = " . $this->literalArray($link->dataReceived) . ';';
            }
            if ($link->tags !== []) {
                $lines[] = "\${$linkVar}->tags = " . $this->literalArray($link->tags) . ';';
            }
        }

        return $lines;
    }

    /** @return list<string> */
    private function writeTrustBoundary(TrustBoundary $boundary, string $var): array
    {
        $lines = [];
        $lines[] = "\${$var} = new TrustBoundary('{$boundary->id}', '" . $this->esc($boundary->name) . "', TrustBoundaryType::{$boundary->type->name});";
        if ($boundary->description !== '') {
            $lines[] = "\${$var}->description = '" . $this->esc($boundary->description) . "';";
        }
        if ($boundary->trustBoundariesNested !== []) {
            $lines[] = "\${$var}->trustBoundariesNested = " . $this->literalArray($boundary->trustBoundariesNested) . ';';
        }
        if ($boundary->tags !== []) {
            $lines[] = "\${$var}->tags = " . $this->literalArray($boundary->tags) . ';';
        }
        if ($boundary->technicalAssetsInside !== []) {
            $lines[] = "\${$var}->addAssets(" . implode(', ', array_map(
                fn (string $id): string => "'" . $this->esc($id) . "'",
                $boundary->technicalAssetsInside,
            )) . ');';
        }
        $lines[] = "\$model->addTrustBoundary(\${$var});";

        return $lines;
    }

    /** @param list<string> $items */
    private function literalArray(array $items): string
    {
        return '[' . implode(', ', array_map(
            fn (string $item): string => "'" . $this->esc($item) . "'",
            $items,
        )) . ']';
    }

    private function literalBool(bool $value): string
    {
        return $value ? 'true' : 'false';
    }

    private function esc(string $value): string
    {
        return str_replace(['\\', "'"], ['\\\\', "\\'"], $value);
    }

    private function camel(string $kebab): string
    {
        return lcfirst(str_replace(' ', '', ucwords(str_replace('-', ' ', $kebab))));
    }

    /** @return list<string> enum short class names actually referenced, sorted */
    private function collectUsedEnums(ThreatModel $model): array
    {
        $enums = ['BusinessCriticality'];

        if ($model->getDataAssets() !== []) {
            $enums = [...$enums, 'DataUsage', 'DataOrigin', 'Quantity', 'Confidentiality', 'Integrity', 'Availability'];
        }
        if ($model->getTechnicalAssets() !== []) {
            $enums = [...$enums, 'AssetType', 'DataUsage', 'Size', 'Technology', 'Machine', 'Encryption', 'Confidentiality', 'Integrity', 'Availability'];
            foreach ($model->getTechnicalAssets() as $asset) {
                if ($asset->communicationLinks !== []) {
                    $enums = [...$enums, 'Protocol', 'Authentication', 'Authorization', 'DataUsage'];
                    break;
                }
            }
        }
        if ($model->getTrustBoundaries() !== []) {
            $enums[] = 'TrustBoundaryType';
        }

        $enums = array_unique($enums);
        sort($enums);
        return $enums;
    }
}
