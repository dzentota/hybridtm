<?php

declare(strict_types=1);

namespace App\Entity;

use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Delete;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Put;
use App\Repository\ModelVersionRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * One snapshot of a project's canonical JSON model (T-6.3). `$version` is
 * Doctrine's optimistic-lock column: API Platform surfaces it as an ETag/
 * If-Match pair automatically, so a stale PUT gets a 409 instead of
 * silently clobbering a concurrent edit.
 */
#[ORM\Entity(repositoryClass: ModelVersionRepository::class)]
#[ORM\Table(name: 'model_version')]
#[ORM\HasLifecycleCallbacks]
#[ApiResource(
    operations: [
        new GetCollection(),
        new Get(security: "is_granted('PROJECT_VIEW', object.project)"),
        new Post(securityPostDenormalize: "is_granted('PROJECT_EDIT_MODEL', object.project)"),
        new Put(securityPostDenormalize: "is_granted('PROJECT_EDIT_MODEL', object.project)"),
        new Delete(security: "is_granted('PROJECT_EDIT_MODEL', object.project)"),
    ],
    order: ['createdAt' => 'DESC'],
    security: "is_granted('ROLE_USER')",
)]
class ModelVersion
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    /** Copied from `project.tenant` on persist (TenantAssignmentListener); never client-writable. */
    #[ApiProperty(writable: false)]
    #[ORM\ManyToOne(targetEntity: Tenant::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public ?Tenant $tenant = null;

    #[ORM\ManyToOne(targetEntity: ThreatModelProject::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    #[Assert\NotNull]
    public ?ThreatModelProject $project = null;

    #[ORM\Column(type: 'integer')]
    public int $schemaVersion = 1;

    /** @var array<string, mixed> canonical JSON model (ModelJsonCodec shape) */
    #[ORM\Column(type: 'json')]
    #[Assert\NotNull]
    public array $data = [];

    /** @var array<string, mixed>|null canvas layout sidecar (LayoutCodec shape) */
    #[ORM\Column(type: 'json', nullable: true)]
    public ?array $layout = null;

    #[ORM\Column(length: 100, nullable: true)]
    public ?string $kbVersion = null;

    #[ApiProperty(writable: false)]
    #[ORM\Column]
    public \DateTimeImmutable $createdAt;

    /**
     * Doctrine's optimistic-lock column — must never be settable from a
     * client payload. If it were, a PUT body that simply echoes back
     * whatever it last read (or omits the field, leaving a fresh-request
     * default) would silently overwrite the real current version instead
     * of the actual database row's version taking part in the lock check.
     */
    #[ApiProperty(writable: false)]
    #[ORM\Version]
    #[ORM\Column(type: 'integer')]
    public int $version = 1;

    public function __construct()
    {
        $this->id = Uuid::v7();
        // See ThreatModelProject::__construct() for why this can't wait for
        // #[ORM\PrePersist] alone.
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): Uuid
    {
        return $this->id;
    }

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
    }
}
