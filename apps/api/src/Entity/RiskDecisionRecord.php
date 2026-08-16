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
use App\Repository\RiskDecisionRecordRepository;
use App\Validator\ValidRiskDecision;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * Persisted form of `HybridTM\Risk\RiskDecision` (T-6.7). Kept as a plain
 * Doctrine entity here rather than persisting the library's value object
 * directly, so the API can query/paginate/filter decisions by project —
 * `toDomain()`/`fromDomain()` are the only bridge to the library type.
 */
#[ORM\Entity(repositoryClass: RiskDecisionRecordRepository::class)]
#[ORM\Table(name: 'risk_decision')]
#[ORM\UniqueConstraint(name: 'project_finding_unique', columns: ['project_id', 'finding_stable_id'])]
#[ORM\HasLifecycleCallbacks]
#[ApiResource(
    operations: [
        new GetCollection(),
        new Get(),
        new Post(security: "is_granted('ROLE_EDITOR')"),
        new Put(security: "is_granted('ROLE_EDITOR')"),
        new Delete(security: "is_granted('ROLE_ADMIN')"),
    ],
    order: ['decidedAt' => 'DESC'],
    security: "is_granted('ROLE_USER')",
)]
#[ValidRiskDecision]
class RiskDecisionRecord
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\ManyToOne(targetEntity: ThreatModelProject::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    #[Assert\NotNull]
    public ?ThreatModelProject $project = null;

    #[ORM\Column(length: 64)]
    #[Assert\NotBlank]
    #[Assert\Regex(pattern: '/^[0-9a-f]{32}$/', message: 'Must be a Finding stableId (32 hex characters).')]
    public string $findingStableId = '';

    #[ORM\Column(length: 20)]
    #[Assert\Choice(choices: ['open', 'accepted', 'mitigated', 'false-positive', 'deferred'])]
    public string $status = 'open';

    #[ORM\Column(type: 'text')]
    #[Assert\Length(min: 20, minMessage: 'Justification must be at least 20 characters — a decision without a real reason is not a decision.')]
    public string $justification = '';

    #[ORM\Column(length: 100, nullable: true)]
    public ?string $ticket = null;

    #[ORM\Column(type: 'date_immutable', nullable: true)]
    public ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column(length: 200)]
    #[Assert\NotBlank]
    public string $decidedBy = '';

    #[ApiProperty(writable: false)]
    #[ORM\Column]
    public \DateTimeImmutable $decidedAt;

    public function __construct()
    {
        $this->id = Uuid::v7();
        // See ThreatModelProject::__construct() for why this can't wait for
        // #[ORM\PrePersist] alone.
        $this->decidedAt = new \DateTimeImmutable();
    }

    public function getId(): Uuid
    {
        return $this->id;
    }

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->decidedAt = new \DateTimeImmutable();
    }
}
