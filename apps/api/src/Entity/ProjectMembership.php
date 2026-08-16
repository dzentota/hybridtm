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
use App\Repository\ProjectMembershipRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * One user's role on one project (T-9.4). The project's creator gets an
 * Admin membership automatically (ProjectMembershipListener); every other
 * membership is explicit — there is no group-inheritance layer yet (the
 * plan's "наследование от групп" is real scope this pass doesn't cover,
 * since it needs a Group entity and a separate propagation rule; flagged
 * rather than half-built).
 */
#[ORM\Entity(repositoryClass: ProjectMembershipRepository::class)]
#[ORM\Table(name: 'project_membership')]
#[ORM\UniqueConstraint(name: 'project_user_unique', columns: ['project_id', 'user_id'])]
#[ApiResource(
    operations: [
        // GetCollection has no single `object` to check against — scoped
        // only by tenant RLS for now, same disclosed simplification as
        // ThreatModelProject's collection read (see its docblock).
        new GetCollection(),
        new Get(security: "is_granted('PROJECT_VIEW', object.project)"),
        new Post(securityPostDenormalize: "is_granted('PROJECT_MANAGE_MEMBERS', object.project)"),
        new Put(securityPostDenormalize: "is_granted('PROJECT_MANAGE_MEMBERS', object.project)"),
        new Delete(security: "is_granted('PROJECT_MANAGE_MEMBERS', object.project)"),
    ],
    security: "is_granted('ROLE_USER')",
)]
class ProjectMembership
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\ManyToOne(targetEntity: ThreatModelProject::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    #[Assert\NotNull]
    public ?ThreatModelProject $project = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    #[Assert\NotNull]
    public ?User $user = null;

    #[ORM\Column(length: 20, enumType: ProjectRole::class)]
    public ProjectRole $role = ProjectRole::Viewer;

    #[ApiProperty(writable: false)]
    #[ORM\ManyToOne(targetEntity: Tenant::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public ?Tenant $tenant = null;

    #[ApiProperty(writable: false)]
    #[ORM\Column]
    public \DateTimeImmutable $createdAt;

    public function __construct()
    {
        $this->id = Uuid::v7();
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): Uuid
    {
        return $this->id;
    }
}
