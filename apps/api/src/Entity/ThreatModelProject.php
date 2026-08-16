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
use App\Repository\ThreatModelProjectRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * A named container for one system's threat model. Holds no model content
 * itself — that lives in its `ModelVersion` history (§6.3, T-6.1/T-6.3).
 */
#[ORM\Entity(repositoryClass: ThreatModelProjectRepository::class)]
#[ORM\Table(name: 'threat_model_project')]
#[ORM\HasLifecycleCallbacks]
#[ApiResource(
    operations: [
        new GetCollection(),
        new Get(security: "is_granted('PROJECT_VIEW', object)"),
        // Any authenticated user may create a project — they become its
        // Admin automatically (ProjectMembershipListener). Collection
        // reads are scoped by tenant via Postgres RLS only, not by
        // per-project membership — a known, disclosed simplification
        // (see ThreatModelProjectRepository/CHANGELOG note); Get/Put/
        // Delete on a specific project are enforced by ProjectVoter
        // regardless.
        new Post(),
        new Put(security: "is_granted('PROJECT_EDIT_MODEL', object)"),
        new Delete(security: "is_granted('PROJECT_DELETE', object)"),
    ],
    order: ['createdAt' => 'DESC'],
    security: "is_granted('ROLE_USER')",
)]
class ThreatModelProject
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    /** Which org this project belongs to (T-9.1); server-derived, never client-writable. */
    #[ApiProperty(writable: false)]
    #[ORM\ManyToOne(targetEntity: Tenant::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public ?Tenant $tenant = null;

    #[ORM\Column(length: 80, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Regex(pattern: '/^[a-z][a-z0-9-]{1,79}$/', message: 'Slug must be a lowercase kebab-case identifier.')]
    public string $slug = '';

    #[ORM\Column(length: 200)]
    #[Assert\NotBlank]
    #[Assert\Length(max: 200)]
    public string $title = '';

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    public ?string $description = null;

    #[ApiProperty(writable: false)]
    #[ORM\Column]
    public \DateTimeImmutable $createdAt;

    #[ApiProperty(writable: false)]
    #[ORM\Column]
    public \DateTimeImmutable $updatedAt;

    public function __construct()
    {
        $this->id = Uuid::v7();
        // Set here, not only in #[ORM\PrePersist]: API Platform's write
        // processor reflects over a bare `new self()` before persisting
        // (for its ETag/If-Match handling), and a typed property with no
        // default throws "must not be accessed before initialization" the
        // moment anything reads it uninitialized — PrePersist runs too
        // late to prevent that. PrePersist still overwrites this with the
        // real persist-time value.
        $this->createdAt = new \DateTimeImmutable();
        $this->updatedAt = $this->createdAt;
    }

    public function getId(): Uuid
    {
        return $this->id;
    }

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $now = new \DateTimeImmutable();
        $this->createdAt = $now;
        $this->updatedAt = $now;
    }

    #[ORM\PreUpdate]
    public function onPreUpdate(): void
    {
        $this->updatedAt = new \DateTimeImmutable();
    }
}
