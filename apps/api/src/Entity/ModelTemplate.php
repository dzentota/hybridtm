<?php

declare(strict_types=1);

namespace App\Entity;

use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Delete;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use App\Repository\ModelTemplateRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * A reusable canvas snapshot (components/boundaries/flows + their canvas
 * layout) a user saved from Studio to drop into other models — the studio
 * "starter templates" gallery previously only offered a handful of
 * hardcoded-in-TypeScript architectures; this is the user-authored
 * counterpart. Deliberately no per-object ACL (unlike ThreatModelProject):
 * a template is shared library content for the whole tenant, same
 * visibility model the KB's own templates would have — any tenant member
 * may read, create, or delete one.
 */
#[ORM\Entity(repositoryClass: ModelTemplateRepository::class)]
#[ORM\Table(name: 'model_template')]
#[ORM\HasLifecycleCallbacks]
#[ApiResource(
    operations: [
        new GetCollection(),
        new Get(),
        new Post(),
        new Delete(),
    ],
    order: ['createdAt' => 'DESC'],
    security: "is_granted('ROLE_USER')",
)]
class ModelTemplate
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    /** Server-derived (T-9.1), never client-writable. */
    #[ApiProperty(writable: false)]
    #[ORM\ManyToOne(targetEntity: Tenant::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public ?Tenant $tenant = null;

    #[ORM\Column(length: 200)]
    #[Assert\NotBlank]
    #[Assert\Length(max: 200)]
    public string $name = '';

    #[ORM\Column(type: Types::TEXT, nullable: true)]
    public ?string $description = null;

    /** @var array<string, mixed> canonical JSON model (ModelJsonCodec shape) */
    #[ORM\Column(type: 'json')]
    #[Assert\NotNull]
    public array $data = [];

    /** @var array<string, mixed>|null canvas layout sidecar (LayoutCodec shape) */
    #[ORM\Column(type: 'json', nullable: true)]
    public ?array $layout = null;

    #[ApiProperty(writable: false)]
    #[ORM\Column]
    public \DateTimeImmutable $createdAt;

    public function __construct()
    {
        $this->id = Uuid::v7();
        // See ThreatModelProject's constructor for why this is set here
        // too, not only in #[ORM\PrePersist].
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
