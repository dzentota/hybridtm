<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\DeepAnalysisResult;
use App\Message\RunDeepAnalysis;
use App\Repository\DeepAnalysisResultRepository;
use App\Repository\ModelVersionRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Routing\Attribute\Route;

/**
 * POST /model-versions/{id}/analyze/deep (T-6.5): kicks off a Threagile-
 * backed deep analysis job on the async message bus and returns
 * immediately with the job's id so the client can poll/stream it (T-6.6)
 * rather than block a request thread on a potentially slow Threagile run.
 *
 * The `DeepAnalysisResult` row is created here, synchronously, precisely
 * so the 202 response can hand back a real id right away — waiting for
 * `RunDeepAnalysisHandler` to create it asynchronously would leave the
 * client with nothing to poll until a worker happens to pick the job up.
 * The handler's own find-or-create looks up this same non-terminal row
 * by model version, so the two never race into duplicates.
 */
final class DeepAnalyzeController
{
    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly DeepAnalysisResultRepository $results,
        private readonly EntityManagerInterface $em,
        private readonly MessageBusInterface $bus,
    ) {
    }

    #[Route('/model-versions/{id}/analyze/deep', name: 'model_version_analyze_deep', methods: ['POST'])]
    public function __invoke(string $id): Response
    {
        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }

        $existing = $this->results->findOneBy(['modelVersion' => $modelVersion], ['createdAt' => 'DESC']);
        if ($existing !== null && !$existing->isTerminal()) {
            $result = $existing;
        } else {
            $result = new DeepAnalysisResult();
            $result->modelVersion = $modelVersion;
            $this->em->persist($result);
            $this->em->flush();
        }

        $this->bus->dispatch(new RunDeepAnalysis($modelVersion->getId()->toRfc4122()));

        return new JsonResponse([
            'id' => $result->getId()->toRfc4122(),
            'status' => $result->status,
        ], Response::HTTP_ACCEPTED);
    }
}
