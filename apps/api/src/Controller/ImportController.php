<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\ModelVersion;
use App\Repository\ThreatModelProjectRepository;
use Doctrine\ORM\EntityManagerInterface;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Codec\OtmCodec;
use HybridTM\Codec\PhpDslReader;
use HybridTM\DSL\ThreatModel;
use HybridTM\Yaml\ThreagileDeserializer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * POST /threat-model-projects/{id}/import/{format} (T-6.8): creates a new
 * ModelVersion under a project from an uploaded model in any of the
 * library's readable formats. PHP DSL import goes through PhpDslReader
 * (AST-based, per ADR-08 — this never `require`s the uploaded file) and
 * surfaces `nonCanonical` constructs as a warning rather than failing,
 * since the reader can still build a partial model from what it
 * recognizes.
 */
final class ImportController
{
    private const FORMATS = ['json', 'php', 'threagile', 'otm'];

    public function __construct(
        private readonly ThreatModelProjectRepository $projects,
        private readonly EntityManagerInterface $em,
        private readonly ModelJsonCodec $jsonCodec,
        private readonly PhpDslReader $phpReader,
        private readonly ThreagileDeserializer $threagileDeserializer,
        private readonly OtmCodec $otmCodec,
    ) {
    }

    #[Route('/threat-model-projects/{id}/import/{format}', name: 'project_import', methods: ['POST'])]
    public function __invoke(string $id, string $format, Request $request): Response
    {
        if (!\in_array($format, self::FORMATS, true)) {
            return new JsonResponse(
                ['error' => "Unknown import format \"{$format}\". Supported: " . implode(', ', self::FORMATS)],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $project = $this->projects->find($id);
        if ($project === null) {
            return new JsonResponse(['error' => 'Project not found'], Response::HTTP_NOT_FOUND);
        }

        $body = $request->getContent();
        $warnings = [];

        try {
            [$model, $warnings] = match ($format) {
                'json' => [$this->jsonCodec->decode(json_decode($body, true, 512, JSON_THROW_ON_ERROR)), []],
                'threagile' => [$this->threagileDeserializer->deserialize($body), []],
                'otm' => [$this->otmCodec->import(json_decode($body, true, 512, JSON_THROW_ON_ERROR)), []],
                'php' => $this->readPhpDsl($body),
            };
        } catch (\Throwable $e) {
            return new JsonResponse(['error' => "Could not parse {$format} input: " . $e->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $modelVersion = new ModelVersion();
        $modelVersion->project = $project;
        $modelVersion->data = $this->jsonCodec->encode($model);
        $this->em->persist($modelVersion);
        $this->em->flush();

        return new JsonResponse([
            'id' => $modelVersion->getId()->toRfc4122(),
            'warnings' => $warnings,
        ], Response::HTTP_CREATED);
    }

    /** @return array{0: ThreatModel, 1: list<string>} */
    private function readPhpDsl(string $code): array
    {
        $result = $this->phpReader->read($code);
        if ($result->model === null) {
            throw new \RuntimeException('PHP DSL contained no recognizable model.');
        }

        $warnings = array_map(
            static fn ($c): string => (string) $c,
            $result->nonCanonical,
        );

        return [$result->model, $warnings];
    }
}
