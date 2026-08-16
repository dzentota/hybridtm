<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\ModelVersionRepository;
use App\Service\KbProvider;
use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Enums\Severity;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * POST /model-versions/{id}/analyze (T-6.4): synchronous fast analysis —
 * decode the stored canonical model, run it through the same RuleEngine
 * used by `hybridtm analyze`/deep analysis, and return findings inline.
 * No persistence here; this is the interactive "check as you edit" path,
 * distinct from the async Threagile-backed deep analysis (T-6.5).
 */
final class AnalyzeController
{
    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly ModelJsonCodec $codec,
        private readonly KbProvider $kbProvider,
        private readonly RuleEngine $engine,
    ) {
    }

    #[Route('/model-versions/{id}/analyze', name: 'model_version_analyze', methods: ['POST'])]
    public function __invoke(string $id): Response
    {
        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }

        $model = $this->codec->decode($modelVersion->data);
        $kb = $this->kbProvider->get();

        $result = $this->engine->analyze($model, $kb, new AnalysisOptions(minSeverity: Severity::Low));

        if ($result->validation->hasErrors()) {
            return new JsonResponse(['validation' => $result->validation], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        return new JsonResponse($result);
    }
}
