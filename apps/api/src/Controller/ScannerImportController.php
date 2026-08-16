<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\RiskDecisionRecord;
use App\Repository\ModelVersionRepository;
use App\Repository\RiskDecisionRecordRepository;
use App\Service\KbProvider;
use Doctrine\ORM\EntityManagerInterface;
use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Enums\Severity;
use HybridTM\Scanner\ScannerReportParser;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Yaml\Yaml;

/**
 * POST /model-versions/{id}/scanner-findings/{tool} (T-10.8): a passing
 * check from a third-party scanner (Checkov/Trivy/SonarQube) that maps to
 * a HybridTM countermeasure automatically closes any open finding that
 * countermeasure would resolve — a verified control in the real
 * environment, not just a property declared in the model, is what
 * "mitigated" should mean. Findings without a decision are left Open;
 * this endpoint only ever *adds* mitigated decisions, never removes or
 * downgrades an existing human decision (accepted/false-positive stay
 * exactly as a reviewer left them).
 */
final class ScannerImportController
{
    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly RiskDecisionRecordRepository $decisions,
        private readonly EntityManagerInterface $em,
        private readonly ModelJsonCodec $codec,
        private readonly KbProvider $kbProvider,
        private readonly RuleEngine $engine,
        private readonly ScannerReportParser $parser,
        private readonly Security $security,
        private readonly string $scannerMappingsPath,
    ) {
    }

    #[Route('/model-versions/{id}/scanner-findings/{tool}', name: 'model_version_scanner_findings', methods: ['POST'])]
    public function __invoke(string $id, string $tool, Request $request): Response
    {
        if (!\in_array($tool, ScannerReportParser::TOOLS, true)) {
            return new JsonResponse(
                ['error' => "Unknown scanner tool \"{$tool}\". Supported: " . implode(', ', ScannerReportParser::TOOLS)],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }
        if (!$this->security->isGranted('PROJECT_DECIDE_RISK', $modelVersion->project)) {
            return new JsonResponse(['error' => 'Access Denied.'], Response::HTTP_FORBIDDEN);
        }

        try {
            $scannerFindings = $this->parser->parse($tool, $request->getContent());
        } catch (\Throwable $e) {
            return new JsonResponse(['error' => "Could not parse {$tool} report: " . $e->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $verifiedCountermeasures = $this->resolveVerifiedCountermeasures($tool, $scannerFindings);
        if ($verifiedCountermeasures === []) {
            return new JsonResponse(['mitigated' => [], 'message' => 'No passing checks mapped to a known countermeasure.']);
        }

        $model = $this->codec->decode($modelVersion->data);
        $result = $this->engine->analyze($model, $this->kbProvider->get(), new AnalysisOptions(minSeverity: Severity::Low));

        $project = $modelVersion->project;
        $mitigated = [];
        foreach ($result->findings as $finding) {
            $resolvedBy = array_values(array_intersect($finding->countermeasureIds, $verifiedCountermeasures));
            if ($resolvedBy === []) {
                continue;
            }

            $existing = $this->decisions->findByProjectAndFinding($project, $finding->stableId);
            if ($existing !== null) {
                continue; // never override an existing human decision
            }

            $decision = new RiskDecisionRecord();
            $decision->project = $project;
            $decision->findingStableId = $finding->stableId;
            $decision->status = 'mitigated';
            $decision->justification = "Automatically closed: {$tool} verified " . implode(', ', $resolvedBy) . ' against the real environment.';
            $decision->decidedBy = "scanner:{$tool}";
            $this->em->persist($decision);

            $mitigated[] = ['findingStableId' => $finding->stableId, 'threatId' => $finding->threatId, 'countermeasures' => $resolvedBy];
        }

        $this->em->flush();

        return new JsonResponse(['mitigated' => $mitigated]);
    }

    /**
     * @param list<\HybridTM\Scanner\ScannerFinding> $scannerFindings
     * @return list<string>
     */
    private function resolveVerifiedCountermeasures(string $tool, array $scannerFindings): array
    {
        if (!is_file($this->scannerMappingsPath)) {
            return [];
        }

        $config = Yaml::parseFile($this->scannerMappingsPath);
        $byRule = [];
        foreach ((array) ($config['mappings'] ?? []) as $mapping) {
            if ($mapping['tool'] === $tool) {
                $byRule[$mapping['rule']] = $mapping['countermeasure'];
            }
        }

        $countermeasures = [];
        foreach ($scannerFindings as $finding) {
            if ($finding->passed && isset($byRule[$finding->ruleId])) {
                $countermeasures[$byRule[$finding->ruleId]] = true;
            }
        }

        return array_keys($countermeasures);
    }
}
