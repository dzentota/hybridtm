<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\ApiTokenRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * Long-lived machine-to-machine credential (T-6.10), distinct from a JWT
 * (short-lived, minted at interactive login). Only the SHA-256 hash is
 * stored — the plaintext token is returned exactly once, at creation time
 * in `ApiTokenController`, and never again.
 */
#[ORM\Entity(repositoryClass: ApiTokenRepository::class)]
#[ORM\Table(name: 'api_token')]
class ApiToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public User $user;

    #[ORM\Column(length: 64, unique: true)]
    public string $tokenHash = '';

    #[ORM\Column(length: 100)]
    public string $label = '';

    #[ORM\Column]
    public \DateTimeImmutable $createdAt;

    #[ORM\Column(nullable: true)]
    public ?\DateTimeImmutable $expiresAt = null;

    public function __construct(User $user)
    {
        $this->id = Uuid::v7();
        $this->user = $user;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): Uuid
    {
        return $this->id;
    }

    public function isExpired(): bool
    {
        return $this->expiresAt !== null && $this->expiresAt < new \DateTimeImmutable();
    }
}
