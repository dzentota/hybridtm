<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\ModelVersionRepository;
use App\Repository\RiskDecisionRecordRepository;
use App\Service\KbProvider;
use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Enums\Severity;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * GET /model-versions/{id}/findings (T-6.7): the fast-analysis findings
 * for a model version, each annotated with its current risk decision (if
 * any project reviewer has recorded one against that finding's stableId).
 * `RiskDecisionRecord` is keyed by (project, findingStableId) rather than
 * by model version, precisely so a decision made against one version
 * survives — and is surfaced here — across later versions where the same
 * underlying finding still reproduces with the same stableId (ADR-12).
 */
final class FindingsController
{
    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly RiskDecisionRecordRepository $decisions,
        private readonly ModelJsonCodec $codec,
        private readonly KbProvider $kbProvider,
        private readonly RuleEngine $engine,
    ) {
    }

    #[Route('/model-versions/{id}/findings', name: 'model_version_findings', methods: ['GET'])]
    public function __invoke(string $id): Response
    {
        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }

        $model = $this->codec->decode($modelVersion->data);
        $result = $this->engine->analyze($model, $this->kbProvider->get(), new AnalysisOptions(minSeverity: Severity::Low));

        if ($result->validation->hasErrors()) {
            return new JsonResponse(['validation' => $result->validation], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $project = $modelVersion->project;
        $decisionsByFinding = [];
        if ($project !== null) {
            foreach ($this->decisions->findByProject($project) as $decision) {
                $decisionsByFinding[$decision->findingStableId] = [
                    'id' => $decision->getId()->toRfc4122(),
                    'status' => $decision->status,
                    'justification' => $decision->justification,
                    'ticket' => $decision->ticket,
                    'expiresAt' => $decision->expiresAt?->format('Y-m-d'),
                    'decidedBy' => $decision->decidedBy,
                    'decidedAt' => $decision->decidedAt->format(\DateTimeInterface::ATOM),
                ];
            }
        }

        $findings = array_map(
            static function ($finding) use ($decisionsByFinding): array {
                $data = $finding->jsonSerialize();
                $data['decision'] = $decisionsByFinding[$finding->stableId] ?? null;
                return $data;
            },
            $result->findings,
        );

        return new JsonResponse([
            'findings' => $findings,
            'summary' => $result->countsBySeverity(),
            'stats' => $result->stats,
        ]);
    }
}
