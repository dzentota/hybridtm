<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\DeepAnalysisResult;
use App\Repository\DeepAnalysisResultRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\Routing\Attribute\Route;

/**
 * GET endpoints for a deep-analysis job started via POST .../analyze/deep
 * (T-6.6). Two shapes of the same read: a plain JSON snapshot for a single
 * check, and an SSE stream that polls the row until it reaches a terminal
 * status — a worker process writes `DeepAnalysisResult` directly via
 * Doctrine, so this request must re-read from the database on every tick
 * rather than trust its own identity map, or it would never see the
 * worker's writes.
 */
final class DeepAnalysisStatusController
{
    private const POLL_INTERVAL_SECONDS = 1;
    private const MAX_STREAM_SECONDS = 120;

    public function __construct(
        private readonly DeepAnalysisResultRepository $results,
        private readonly EntityManagerInterface $em,
    ) {
    }

    #[Route('/deep-analysis-results/{id}', name: 'deep_analysis_result_get', methods: ['GET'])]
    public function get(string $id): Response
    {
        $result = $this->results->find($id);
        if ($result === null) {
            return new JsonResponse(['error' => 'Deep analysis result not found'], Response::HTTP_NOT_FOUND);
        }

        return new JsonResponse($this->snapshot($result));
    }

    #[Route('/deep-analysis-results/{id}/events', name: 'deep_analysis_result_events', methods: ['GET'])]
    public function events(string $id): Response
    {
        $result = $this->results->find($id);
        if ($result === null) {
            return new JsonResponse(['error' => 'Deep analysis result not found'], Response::HTTP_NOT_FOUND);
        }

        $response = new StreamedResponse(function () use ($id): void {
            $lastStatus = null;
            $elapsed = 0;

            while (true) {
                $this->em->clear();
                $result = $this->results->find($id);
                if ($result === null) {
                    $this->emit('error', ['error' => 'Deep analysis result not found']);
                    break;
                }

                if ($result->status !== $lastStatus) {
                    $lastStatus = $result->status;
                    $this->emit('status', $this->snapshot($result));
                }

                if ($result->isTerminal()) {
                    break;
                }

                if ($elapsed >= self::MAX_STREAM_SECONDS) {
                    $this->emit('timeout', ['status' => $lastStatus]);
                    break;
                }

                sleep(self::POLL_INTERVAL_SECONDS);
                $elapsed += self::POLL_INTERVAL_SECONDS;
            }
        });

        $response->headers->set('Content-Type', 'text/event-stream');
        $response->headers->set('Cache-Control', 'no-cache');
        $response->headers->set('X-Accel-Buffering', 'no');

        return $response;
    }

    /** @param array<string, mixed> $data */
    private function emit(string $event, array $data): void
    {
        echo "event: {$event}\n";
        echo 'data: ' . json_encode($data, JSON_THROW_ON_ERROR) . "\n\n";
        if (ob_get_level() > 0) {
            ob_flush();
        }
        flush();
    }

    /** @return array<string, mixed> */
    private function snapshot(DeepAnalysisResult $result): array
    {
        return [
            'id' => $result->getId()->toRfc4122(),
            'status' => $result->status,
            'findings' => $result->findings,
            'error' => $result->error,
            'completedAt' => $result->completedAt?->format(\DateTimeInterface::ATOM),
        ];
    }
}
