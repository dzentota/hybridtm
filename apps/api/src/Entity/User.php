<?php

declare(strict_types=1);

namespace App\Entity;

use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Get;
use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Basic RBAC (T-6.10): three roles — ROLE_USER (read), ROLE_EDITOR (create/
 * modify model versions, risk decisions, imports), ROLE_ADMIN (mint API
 * tokens for other users, tenant admin — bypasses ProjectVoter checks).
 * Project-level permissions (Viewer/Modeler/Reviewer/KbAuthor/Admin) are
 * T-9.4's ProjectMembership, layered on top of these.
 *
 * Read-only API resource: there's no self-service registration or
 * profile-editing endpoint by design (account creation is
 * app:create-user only) — this exists so relations like
 * ProjectMembership.user can resolve a `/api/users/{id}` IRI to the
 * managed entity. Without it, API Platform can't tell that IRI refers to
 * an existing row and denormalizes a transient, unmanaged User instead,
 * which Doctrine then rejects at flush time as an unexpected new entity.
 */
#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'app_user')]
#[ApiResource(
    // Deliberately Get-only, no GetCollection: app_user carries no RLS
    // policy (login must look a user up by email before it can know
    // their tenant), so a collection listing would leak every tenant's
    // users to any ROLE_ADMIN, not just the caller's own tenant. A
    // same-tenant "list members" endpoint is real scope for later, not
    // silently done here.
    operations: [
        new Get(),
    ],
    security: "is_granted('ROLE_USER')",
)]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    /** Which org this account belongs to (T-9.1) — one tenant per user in this pass. */
    #[ApiProperty(writable: false)]
    #[ORM\ManyToOne(targetEntity: Tenant::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public ?Tenant $tenant = null;

    #[ApiProperty(writable: false)]
    #[ORM\Column(length: 180, unique: true)]
    public string $email = '';

    #[ApiProperty(readable: false, writable: false)]
    #[ORM\Column]
    public string $password = '';

    /** @var list<string> */
    #[ApiProperty(writable: false)]
    #[ORM\Column]
    public array $roles = [];

    public function __construct()
    {
        $this->id = Uuid::v7();
    }

    public function getId(): Uuid
    {
        return $this->id;
    }

    public function getUserIdentifier(): string
    {
        return $this->email;
    }

    /** @return list<string> */
    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_USER';

        return array_values(array_unique($roles));
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function eraseCredentials(): void
    {
    }
}
