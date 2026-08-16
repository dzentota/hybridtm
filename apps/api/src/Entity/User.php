<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Basic RBAC (T-6.10): three roles — ROLE_USER (read), ROLE_EDITOR (create/
 * modify model versions, risk decisions, imports), ROLE_ADMIN (mint API
 * tokens for other users). Deliberately not the full 5-role, group-
 * inheriting model — that's T-9.4, once multi-tenancy (E9) exists to scope
 * it against. `roles` always includes ROLE_USER implicitly, matching
 * Symfony's own convention.
 */
#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'app_user')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\Column(length: 180, unique: true)]
    public string $email = '';

    #[ORM\Column]
    public string $password = '';

    /** @var list<string> */
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
