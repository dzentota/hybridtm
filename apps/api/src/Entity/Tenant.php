<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\TenantRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * A customer organization (T-9.1). Every tenant-scoped row carries a
 * tenant_id column and a Postgres row-level security policy enforces
 * isolation at the database layer — application code does not need its
 * own "does this belong to my tenant" checks, and cannot forget to add
 * one to a new query path.
 */
#[ORM\Entity(repositoryClass: TenantRepository::class)]
#[ORM\Table(name: 'tenant')]
class Tenant
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\Column(length: 80, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Regex(pattern: '/^[a-z][a-z0-9-]{1,79}$/', message: 'Slug must be a lowercase kebab-case identifier.')]
    public string $slug = '';

    #[ORM\Column(length: 200)]
    #[Assert\NotBlank]
    public string $name = '';

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
