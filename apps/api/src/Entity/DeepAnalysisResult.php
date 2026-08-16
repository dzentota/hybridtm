<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\DeepAnalysisResultRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * Tracks one `POST /model-versions/{id}/analyze/deep` job (T-6.5/T-6.6):
 * created `pending`, flipped to `running` then `completed`/`failed` by
 * `RunDeepAnalysisHandler`. The SSE endpoint polls this row for status
 * changes to stream progress to the client.
 */
#[ORM\Entity(repositoryClass: DeepAnalysisResultRepository::class)]
#[ORM\Table(name: 'deep_analysis_result')]
class DeepAnalysisResult
{
    public const STATUS_PENDING = 'pending';
    public const STATUS_RUNNING = 'running';
    public const STATUS_COMPLETED = 'completed';
    public const STATUS_FAILED = 'failed';

    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\ManyToOne(targetEntity: ModelVersion::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    public ?ModelVersion $modelVersion = null;

    #[ORM\Column(length: 20)]
    public string $status = self::STATUS_PENDING;

    /** @var array<int, mixed>|null decoded Finding::jsonSerialize() list once completed */
    #[ORM\Column(type: 'json', nullable: true)]
    public ?array $findings = null;

    #[ORM\Column(type: 'text', nullable: true)]
    public ?string $error = null;

    #[ORM\Column]
    public \DateTimeImmutable $createdAt;

    #[ORM\Column(nullable: true)]
    public ?\DateTimeImmutable $completedAt = null;

    public function __construct()
    {
        $this->id = Uuid::v7();
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): Uuid
    {
        return $this->id;
    }

    public function isTerminal(): bool
    {
        return \in_array($this->status, [self::STATUS_COMPLETED, self::STATUS_FAILED], true);
    }
}
