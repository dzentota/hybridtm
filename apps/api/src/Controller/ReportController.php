<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\ModelVersionRepository;
use App\Report\DocxReportGenerator;
use App\Report\PdfReportGenerator;
use App\Report\ReportData;
use App\Report\XlsxReportGenerator;
use App\Service\KbProvider;
use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Enums\Severity;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * GET /model-versions/{id}/report/{format} (T-10.2/T-10.3): title,
 * summary, DFD, risk register, countermeasures, and standards appendix
 * in PDF, DOCX, or XLSX. Generated synchronously, not in an isolated
 * worker as the plan specifies for the PDF report — a deliberate
 * simplification given the model sizes this pass has to work with;
 * a real deployment would move this behind the same Messenger-worker
 * pattern DeepAnalyzeController already uses once report generation
 * time/resource cost justifies it.
 */
final class ReportController
{
    private const CONTENT_TYPES = [
        'pdf' => 'application/pdf',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];

    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly ModelJsonCodec $codec,
        private readonly KbProvider $kbProvider,
        private readonly RuleEngine $engine,
        private readonly PdfReportGenerator $pdfGenerator,
        private readonly DocxReportGenerator $docxGenerator,
        private readonly XlsxReportGenerator $xlsxGenerator,
        private readonly Security $security,
    ) {
    }

    #[Route('/model-versions/{id}/report/{format}', name: 'model_version_report', methods: ['GET'])]
    public function __invoke(string $id, string $format): Response
    {
        if (!isset(self::CONTENT_TYPES[$format])) {
            return new JsonResponse(
                ['error' => "Unknown report format \"{$format}\". Supported: " . implode(', ', array_keys(self::CONTENT_TYPES))],
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

        $model = $this->codec->decode($modelVersion->data);
        $result = $this->engine->analyze($model, $this->kbProvider->get(), new AnalysisOptions(minSeverity: Severity::Low));

        $data = new ReportData(
            projectTitle: $modelVersion->project?->title ?? '',
            modelTitle: $model->title,
            model: $model,
            result: $result,
            generatedAt: new \DateTimeImmutable(),
        );

        $bytes = match ($format) {
            'pdf' => $this->pdfGenerator->generate($data),
            'docx' => $this->docxGenerator->generate($data),
            'xlsx' => $this->xlsxGenerator->generate($data),
        };

        $response = new Response($bytes);
        $response->headers->set('Content-Type', self::CONTENT_TYPES[$format]);
        $response->headers->set('Content-Disposition', "attachment; filename=\"report-{$id}.{$format}\"");

        return $response;
    }
}
