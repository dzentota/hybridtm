<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\ModelVersionRepository;
use App\Service\KbProvider;
use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\AnalysisResult;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\GraphvizExporter;
use HybridTM\Codec\MermaidExporter;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Codec\OtmCodec;
use HybridTM\Codec\PhpDslWriter;
use HybridTM\Codec\SarifCodec;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\Severity;
use HybridTM\Yaml\ThreagileSerializer;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * GET /model-versions/{id}/export/{format} (T-6.8, extended by T-10.1/
 * T-10.4): re-renders a stored model version in any of the library's
 * round-trip formats, plus two reporting/diagram formats that don't
 * round-trip (sarif, mermaid, dot are one-way exports, never importable
 * back into a model). The PHP DSL is the source of truth (ADR-06) and
 * Threagile/OTM are exchange formats (ADR-13) — this endpoint just
 * exposes codecs the library already has, it does not add new
 * serialization logic of its own.
 */
final class ExportController
{
    private const FORMATS = ['json', 'php', 'threagile', 'otm', 'sarif', 'mermaid', 'dot'];

    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly ModelJsonCodec $jsonCodec,
        private readonly PhpDslWriter $phpWriter,
        private readonly ThreagileSerializer $threagileSerializer,
        private readonly OtmCodec $otmCodec,
        private readonly SarifCodec $sarifCodec,
        private readonly MermaidExporter $mermaidExporter,
        private readonly GraphvizExporter $graphvizExporter,
        private readonly KbProvider $kbProvider,
        private readonly RuleEngine $engine,
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
            'sarif' => new JsonResponse($this->sarifCodec->export($this->analyze($model))),
            'mermaid' => new Response($this->mermaidExporter->export($model), Response::HTTP_OK, ['Content-Type' => 'text/plain']),
            'dot' => new Response($this->graphvizExporter->export($model), Response::HTTP_OK, ['Content-Type' => 'text/vnd.graphviz']),
        };
    }

    private function analyze(ThreatModel $model): AnalysisResult
    {
        return $this->engine->analyze($model, $this->kbProvider->get(), new AnalysisOptions(minSeverity: Severity::Low));
    }
}
