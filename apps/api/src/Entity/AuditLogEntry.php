<?php

declare(strict_types=1);

namespace App\Entity;

use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * Append-only audit trail (T-9.5): who changed what, when, and how — one
 * row per create/update/delete of a tenant-scoped entity. `patch` is a
 * JSON Patch (RFC 6902) document; replaying every entry's patch in order
 * against the entity's initial state reconstructs its full history, which
 * is the acceptance criterion ("any model change is recoverable from the
 * log"). Read-only API resource by design — nothing may ever update or
 * delete an audit row, including via the API; only AuditLogListener
 * writes to this table. SIEM export is just "read this endpoint" — no
 * dedicated shipper is built here.
 */
#[ORM\Entity]
#[ORM\Table(name: 'audit_log_entry')]
#[ApiResource(
    operations: [
        new GetCollection(security: "is_granted('ROLE_ADMIN')"),
        new Get(security: "is_granted('ROLE_ADMIN')"),
    ],
    order: ['occurredAt' => 'DESC'],
)]
class AuditLogEntry
{
    public const ACTION_CREATE = 'create';
    public const ACTION_UPDATE = 'update';
    public const ACTION_DELETE = 'delete';

    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\ManyToOne(targetEntity: Tenant::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public ?Tenant $tenant = null;

    /** Email at the time of the change — not a FK, so the log survives account deletion. */
    #[ORM\Column(length: 180, nullable: true)]
    public ?string $actorEmail = null;

    #[ORM\Column(length: 20)]
    public string $action = self::ACTION_UPDATE;

    /** Short class name, e.g. "ThreatModelProject" — not the FQCN, which is an implementation detail. */
    #[ORM\Column(length: 100)]
    public string $entityType = '';

    #[ORM\Column(type: 'uuid')]
    public ?Uuid $entityId = null;

    /** @var array<int, array<string, mixed>> RFC 6902 JSON Patch operations */
    #[ORM\Column(type: 'json')]
    public array $patch = [];

    #[ORM\Column(length: 45, nullable: true)]
    public ?string $ipAddress = null;

    #[ORM\Column]
    public \DateTimeImmutable $occurredAt;

    public function __construct()
    {
        $this->id = Uuid::v7();
        $this->occurredAt = new \DateTimeImmutable();
    }

    public function getId(): Uuid
    {
        return $this->id;
    }
}
