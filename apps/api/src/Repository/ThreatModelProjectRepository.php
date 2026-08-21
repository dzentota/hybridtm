<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\ThreatModelProject;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<ThreatModelProject>
 */
final class ThreatModelProjectRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, ThreatModelProject::class);
    }

    public function findBySlug(string $slug): ?ThreatModelProject
    {
        return $this->findOneBy(['slug' => $slug]);
    }
}
