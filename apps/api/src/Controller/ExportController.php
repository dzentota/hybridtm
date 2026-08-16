<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\ModelVersionRepository;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Codec\OtmCodec;
use HybridTM\Codec\PhpDslWriter;
use HybridTM\Yaml\ThreagileSerializer;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * GET /model-versions/{id}/export/{format} (T-6.8): re-renders a stored
 * model version in any of the library's round-trip formats. The PHP DSL
 * is the source of truth (ADR-06) and Threagile/OTM are exchange formats
 * (ADR-13) — this endpoint just exposes codecs the library already has,
 * it does not add new serialization logic of its own.
 */
final class ExportController
{
    private const FORMATS = ['json', 'php', 'threagile', 'otm'];

    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly ModelJsonCodec $jsonCodec,
        private readonly PhpDslWriter $phpWriter,
        private readonly ThreagileSerializer $threagileSerializer,
        private readonly OtmCodec $otmCodec,
        private readonly Security $security,
    ) {
    }

    #[Route('/model-versions/{id}/export/{format}', name: 'model_version_export', methods: ['GET'])]
    public function __invoke(string $id, string $format): Response
    {
        if (!\in_array($format, self::FORMATS, true)) {
            return new JsonResponse(
                ['error' => "Unknown export format \"{$format}\". Supported: " . implode(', ', self::FORMATS)],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }

        if (!$this->security->isGranted('PROJECT_VIEW', $modelVersion->project)) {
            return new JsonResponse(['error' => 'Access Denied.'], Response::HTTP_FORBIDDEN);
        }

        $model = $this->jsonCodec->decode($modelVersion->data);

        return match ($format) {
            'json' => new JsonResponse($modelVersion->data),
            'php' => new Response($this->phpWriter->write($model), Response::HTTP_OK, ['Content-Type' => 'text/x-php']),
            'threagile' => new Response($this->threagileSerializer->serialize($model), Response::HTTP_OK, ['Content-Type' => 'application/yaml']),
            'otm' => new JsonResponse($this->otmCodec->export($model)),
        };
    }
}
