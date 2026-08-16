<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\ModelVersion;
use App\Entity\ThreatModelProject;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<ModelVersion>
 */
final class ModelVersionRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, ModelVersion::class);
    }

    public function findLatestFor(ThreatModelProject $project): ?ModelVersion
    {
        return $this->createQueryBuilder('v')
            ->andWhere('v.project = :project')
            ->setParameter('project', $project)
            ->orderBy('v.createdAt', 'DESC')
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }
}
