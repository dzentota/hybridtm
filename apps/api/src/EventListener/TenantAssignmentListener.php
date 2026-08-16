<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\DeepAnalysisResult;
use App\Entity\ModelVersion;
use App\Entity\ProjectMembership;
use App\Entity\RiskDecisionRecord;
use App\Entity\Tenant;
use App\Entity\ThreatModelProject;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsDoctrineListener;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Events;
use Symfony\Bundle\SecurityBundle\Security;

/**
 * Stamps `tenant` on every tenant-scoped entity before insert (T-9.1).
 * `tenant` is never client-writable (see each entity's ApiProperty), so
 * this is the only place it gets set — either from the acting user's own
 * tenant (for a brand-new ThreatModelProject) or from the parent
 * project's tenant (for anything hanging off one), which is what a
 * Postgres row-level security policy actually checks against.
 */
#[AsDoctrineListener(event: Events::prePersist)]
final class TenantAssignmentListener
{
    public function __construct(private readonly Security $security)
    {
    }

    public function prePersist(PrePersistEventArgs $args): void
    {
        $entity = $args->getObject();

        if ($entity instanceof ThreatModelProject) {
            $entity->tenant ??= $this->currentTenant();
            return;
        }

        if ($entity instanceof ModelVersion) {
            $entity->tenant ??= $entity->project?->tenant;
            return;
        }

        if ($entity instanceof RiskDecisionRecord) {
            $entity->tenant ??= $entity->project?->tenant;
            return;
        }

        if ($entity instanceof DeepAnalysisResult) {
            $entity->tenant ??= $entity->modelVersion?->project?->tenant;
            return;
        }

        if ($entity instanceof ProjectMembership) {
            $entity->tenant ??= $entity->project?->tenant;
        }
    }

    private function currentTenant(): ?Tenant
    {
        $user = $this->security->getUser();
        return $user instanceof User ? $user->tenant : null;
    }
}
