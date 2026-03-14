<?php
declare(strict_types=1);
namespace HybridTM\Compiler;

use HybridTM\DSL\CommunicationLink;
use HybridTM\DSL\ThreatModel;
use RuntimeException;

final class Linker
{
    /** @var string[] */
    private array $warnings = [];

    public function link(ThreatModel $model, AstResult $ast): void
    {
        foreach ($ast->dataFlows as $flow) {
            $source = $flow->sourceAssetId !== '' ? $model->getTechnicalAsset($flow->sourceAssetId) : null;
            $target = $model->getTechnicalAsset($flow->targetAssetId);

            if ($target === null) {
                throw new RuntimeException(
                    "[DataFlow@{$flow->context}] Unknown target asset '{$flow->targetAssetId}'. " .
                    "Add it to your threat model DSL file."
                );
            }

            if ($source === null) {
                $this->warnings[] = "[DataFlow@{$flow->context}] No source asset specified (add #[AssetId('asset-id')] to the class). " .
                    "DataFlow to '{$flow->targetAssetId}' will be recorded on the target asset only.";
                foreach ($flow->dataSent as $dataId) {
                    if ($model->getDataAsset($dataId) === null) {
                        throw new RuntimeException("[DataFlow@{$flow->context}] Unknown DataAsset '{$dataId}' in dataSent.");
                    }
                    if (!in_array($dataId, $target->dataAssetsProcessed, true)) {
                        $target->dataAssetsProcessed[] = $dataId;
                    }
                }
                continue;
            }

            foreach ([...$flow->dataSent, ...$flow->dataReceived] as $dataId) {
                if ($model->getDataAsset($dataId) === null) {
                    throw new RuntimeException("[DataFlow@{$flow->context}] Unknown DataAsset '{$dataId}'. Add it to the threat model DSL.");
                }
            }

            $linkId = $source->id . '-to-' . $target->id;
            if (!isset($source->communicationLinks[$linkId])) {
                $link = new CommunicationLink($linkId, $target->id, $flow->protocol, $flow->authentication, $flow->authorization);
                $link->vpn = $flow->vpn;
                $link->ipFiltered = $flow->ipFiltered;
                $link->readonly = $flow->readonly;
                $source->communicationLinks[$linkId] = $link;
            }

            $link = $source->communicationLinks[$linkId];
            foreach ($flow->dataSent as $id) {
                if (!in_array($id, $link->dataSent, true)) $link->dataSent[] = $id;
                if (!in_array($id, $source->dataAssetsProcessed, true)) $source->dataAssetsProcessed[] = $id;
            }
            foreach ($flow->dataReceived as $id) {
                if (!in_array($id, $link->dataReceived, true)) $link->dataReceived[] = $id;
                if (!in_array($id, $source->dataAssetsProcessed, true)) $source->dataAssetsProcessed[] = $id;
            }
        }

        foreach ($ast->processesData as $pd) {
            foreach ($pd->dataAssets as $dataId) {
                if ($model->getDataAsset($dataId) === null) {
                    $this->warnings[] = "[ProcessesData@{$pd->context}] Unknown DataAsset '{$dataId}'. Skipping.";
                }
            }
        }
    }

    /** @return string[] */
    public function getWarnings(): array
    {
        return $this->warnings;
    }
}
