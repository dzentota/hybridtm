<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\ModelVersionStatus;
use App\Policy\PolicyEngine;
use App\Repository\ModelVersionRepository;
use App\Service\KbProvider;
use Doctrine\ORM\EntityManagerInterface;
use HybridTM\Analysis\AnalysisOptions;
use HybridTM\Analysis\RuleEngine;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Enums\Severity;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Model version workflow transitions (T-9.6): Draft -> InReview ->
 * Approved -> Superseded. Approving also supersedes whatever version was
 * previously Approved for the same project — only one Approved version
 * per project at a time, matching a governance model where "the approved
 * model" is a single, unambiguous thing to point an auditor at.
 */
final class WorkflowController
{
    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly EntityManagerInterface $em,
        private readonly Security $security,
        private readonly ModelJsonCodec $codec,
        private readonly KbProvider $kbProvider,
        private readonly RuleEngine $engine,
        private readonly PolicyEngine $policyEngine,
    ) {
    }

    #[Route('/model-versions/{id}/submit-for-review', name: 'model_version_submit_for_review', methods: ['POST'])]
    public function submitForReview(string $id): Response
    {
        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }
        if (!$this->security->isGranted('PROJECT_EDIT_MODEL', $modelVersion->project)) {
            return new JsonResponse(['error' => 'Access Denied.'], Response::HTTP_FORBIDDEN);
        }
        if ($modelVersion->status !== ModelVersionStatus::Draft) {
            return new JsonResponse(['error' => "Cannot submit for review from status \"{$modelVersion->status->value}\"; only Draft can be submitted."], Response::HTTP_CONFLICT);
        }

        $modelVersion->status = ModelVersionStatus::InReview;
        $this->em->flush();

        return new JsonResponse(['id' => $id, 'status' => $modelVersion->status->value]);
    }

    #[Route('/model-versions/{id}/request-changes', name: 'model_version_request_changes', methods: ['POST'])]
    public function requestChanges(string $id): Response
    {
        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }
        if (!$this->security->isGranted('PROJECT_DECIDE_RISK', $modelVersion->project)) {
            return new JsonResponse(['error' => 'Access Denied.'], Response::HTTP_FORBIDDEN);
        }
        if ($modelVersion->status !== ModelVersionStatus::InReview) {
            return new JsonResponse(['error' => "Cannot request changes from status \"{$modelVersion->status->value}\"; only In Review can be sent back."], Response::HTTP_CONFLICT);
        }

        $modelVersion->status = ModelVersionStatus::Draft;
        $this->em->flush();

        return new JsonResponse(['id' => $id, 'status' => $modelVersion->status->value]);
    }

    #[Route('/model-versions/{id}/approve', name: 'model_version_approve', methods: ['POST'])]
    public function approve(string $id): Response
    {
        $modelVersion = $this->modelVersions->find($id);
        if ($modelVersion === null) {
            return new JsonResponse(['error' => 'Model version not found'], Response::HTTP_NOT_FOUND);
        }
        if (!$this->security->isGranted('PROJECT_DECIDE_RISK', $modelVersion->project)) {
            return new JsonResponse(['error' => 'Access Denied.'], Response::HTTP_FORBIDDEN);
        }
        if ($modelVersion->status !== ModelVersionStatus::InReview) {
            return new JsonResponse(['error' => "Cannot approve from status \"{$modelVersion->status->value}\"; only In Review can be approved."], Response::HTTP_CONFLICT);
        }

        $model = $this->codec->decode($modelVersion->data);
        $result = $this->engine->analyze($model, $this->kbProvider->get(), new AnalysisOptions(minSeverity: Severity::Low));
        $violations = $this->policyEngine->evaluate($model, $result);

        if ($violations !== []) {
            return new JsonResponse([
                'error' => 'Policy violations block approval.',
                'violations' => array_map(
                    static fn ($v) => ['policyId' => $v->policyId, 'description' => $v->description, 'subject' => $v->subject, 'reason' => $v->reason],
                    $violations,
                ),
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $previouslyApproved = $this->modelVersions->findOneBy([
            'project' => $modelVersion->project,
            'status' => ModelVersionStatus::Approved,
        ]);
        if ($previouslyApproved !== null) {
            $previouslyApproved->status = ModelVersionStatus::Superseded;
        }

        $modelVersion->status = ModelVersionStatus::Approved;
        $this->em->flush();

        return new JsonResponse(['id' => $id, 'status' => $modelVersion->status->value]);
    }
}
