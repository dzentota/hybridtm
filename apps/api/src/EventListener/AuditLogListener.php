<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\AuditLogEntry;
use App\Entity\ModelVersion;
use App\Entity\RiskDecisionRecord;
use App\Entity\Tenant;
use App\Entity\ThreatModelProject;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsDoctrineListener;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Events;
use Doctrine\ORM\Mapping\ClassMetadata;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Uid\Uuid;

/**
 * Builds one AuditLogEntry per create/update/delete of a governed entity
 * (T-9.5), each entry's `patch` a JSON Patch (RFC 6902) fragment — a
 * create's patch is the whole entity, an update's is one `replace` per
 * changed scalar/json field, a delete's is a single `remove`. Runs on
 * `onFlush` (not `postPersist`/`postUpdate`) specifically so the new
 * AuditLogEntry rows can be scheduled into the *same* flush via
 * `computeChangeSet` + `scheduleForInsert` — no nested flush() call,
 * unlike ProjectMembershipListener, since onFlush fires before the SQL
 * for this flush has been issued at all.
 */
#[AsDoctrineListener(event: Events::onFlush)]
final class AuditLogListener
{
    /** @var class-string[] */
    private const GOVERNED = [ThreatModelProject::class, ModelVersion::class, RiskDecisionRecord::class];

    public function __construct(
        private readonly Security $security,
        private readonly RequestStack $requestStack,
    ) {
    }

    public function onFlush(OnFlushEventArgs $args): void
    {
        $em = $args->getObjectManager();
        $uow = $em->getUnitOfWork();

        $entries = [];

        foreach ($uow->getScheduledEntityInsertions() as $entity) {
            if ($this->isGoverned($entity)) {
                $snapshot = $this->toArray($entity, $em->getClassMetadata($entity::class));
                $entries[] = $this->buildEntry($entity, AuditLogEntry::ACTION_CREATE, [['op' => 'add', 'path' => '', 'value' => $snapshot]]);
            }
        }

        foreach ($uow->getScheduledEntityUpdates() as $entity) {
            if (!$this->isGoverned($entity)) {
                continue;
            }
            $changeSet = $uow->getEntityChangeSet($entity);
            $patch = [];
            foreach ($changeSet as $field => [, $newValue]) {
                if (\is_object($newValue) || \is_array($newValue) && $this->containsObject($newValue)) {
                    continue;
                }
                $patch[] = ['op' => 'replace', 'path' => '/' . $field, 'value' => $newValue];
            }
            if ($patch !== []) {
                $entries[] = $this->buildEntry($entity, AuditLogEntry::ACTION_UPDATE, $patch);
            }
        }

        foreach ($uow->getScheduledEntityDeletions() as $entity) {
            if ($this->isGoverned($entity)) {
                $entries[] = $this->buildEntry($entity, AuditLogEntry::ACTION_DELETE, [['op' => 'remove', 'path' => '']]);
            }
        }

        if ($entries === []) {
            return;
        }

        $metadata = $em->getClassMetadata(AuditLogEntry::class);
        foreach ($entries as $entry) {
            $em->persist($entry);
            $uow->computeChangeSet($metadata, $entry);
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

    /** @param array<int, array<string, mixed>> $patch */
    private function buildEntry(object $entity, string $action, array $patch): AuditLogEntry
    {
        $entry = new AuditLogEntry();
        $entry->tenant = $this->tenantOf($entity);
        $entry->actorEmail = $this->currentUserEmail();
        $entry->action = $action;
        $entry->entityType = (new \ReflectionClass($entity))->getShortName();
        $entry->entityId = $this->idOf($entity);
        $entry->patch = $patch;
        $entry->ipAddress = $this->requestStack->getCurrentRequest()?->getClientIp();

        return $entry;
    }

    private function tenantOf(object $entity): ?Tenant
    {
        return match (true) {
            $entity instanceof ThreatModelProject => $entity->tenant,
            $entity instanceof ModelVersion => $entity->tenant,
            $entity instanceof RiskDecisionRecord => $entity->tenant,
            default => null,
        };
    }

    private function idOf(object $entity): ?Uuid
    {
        if (!method_exists($entity, 'getId')) {
            return null;
        }
        $id = $entity->getId();
        return $id instanceof Uuid ? $id : null;
    }

    private function currentUserEmail(): ?string
    {
        $user = $this->security->getUser();
        return $user instanceof User ? $user->email : null;
    }

    /** @return array<string, mixed> */
    private function toArray(object $entity, ClassMetadata $metadata): array
    {
        $data = [];
        foreach ($metadata->getFieldNames() as $field) {
            $value = $metadata->getFieldValue($entity, $field);
            if ($value instanceof \DateTimeInterface) {
                $data[$field] = $value->format(\DateTimeInterface::ATOM);
                continue;
            }
            if (\is_array($value) && $this->containsObject($value)) {
                continue;
            }
            if (\is_object($value)) {
                continue;
            }
            $data[$field] = $value;
        }
        return $data;
    }

    private function containsObject(array $value): bool
    {
        foreach ($value as $item) {
            if (\is_object($item)) {
                return true;
            }
        }
        return false;
    }
}
