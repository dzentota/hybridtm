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
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Events;
use Symfony\Bundle\SecurityBundle\Security;

/**
 * Stamps `tenant` on every tenant-scoped entity before insert (T-9.1), and
 * repairs it on update if it came back null (T-9.1 bugfix, see below).
 * `tenant` is never client-writable (see each entity's ApiProperty), so
 * this is the only place it gets set — either from the acting user's own
 * tenant (for a brand-new ThreatModelProject) or from the parent
 * project's tenant (for anything hanging off one), which is what a
 * Postgres row-level security policy actually checks against.
 *
 * `onFlush` runs the repair (not `preUpdate`): API Platform's PUT
 * pipeline leaves `tenant` null on the in-memory entity despite
 * `writable: false` marking it non-denormalizable — Doctrine's own
 * changeset computation (which runs before `onFlush` fires) faithfully
 * records this as a real change, from the original Tenant to null. By
 * the time `preUpdate` would fire per-entity, AuditLogListener's onFlush
 * handler (registered after this one) has already read the corrupted
 * null and tried to insert an audit row with a null tenant, which the
 * row-level security policy on audit_log_entry rejects outright —
 * failing the whole request before `preUpdate` is ever reached. Fixing
 * it here, earlier in the same event, is what makes the repair visible
 * to every other onFlush-time listener, not just to Doctrine's own SQL
 * generation.
 */
#[AsDoctrineListener(event: Events::prePersist)]
#[AsDoctrineListener(event: Events::onFlush, priority: 10)]
final class TenantAssignmentListener
{
    private const GOVERNED = [ThreatModelProject::class, ModelVersion::class, RiskDecisionRecord::class, ProjectMembership::class];

    public function __construct(private readonly Security $security)
    {
    }

    public function onFlush(OnFlushEventArgs $args): void
    {
        $em = $args->getObjectManager();
        $uow = $em->getUnitOfWork();
        $conn = $em->getConnection();

        foreach ($uow->getScheduledEntityUpdates() as $entity) {
            if (!$this->isGoverned($entity) || $entity->tenant !== null) {
                continue;
            }

            $table = $em->getClassMetadata($entity::class)->getTableName();
            $tenantId = $conn->fetchOne("SELECT tenant_id FROM {$table} WHERE id = ?", [$entity->getId()->toRfc4122()]);
            if ($tenantId === false || $tenantId === null) {
                continue;
            }

            $entity->tenant = $em->getReference(Tenant::class, $tenantId);
            $uow->recomputeSingleEntityChangeSet($em->getClassMetadata($entity::class), $entity);
        }
    }

    private function isGoverned(object $entity): bool
    {
        foreach (self::GOVERNED as $class) {
            if ($entity instanceof $class) {
                return true;
            }
        }
        return false;
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
