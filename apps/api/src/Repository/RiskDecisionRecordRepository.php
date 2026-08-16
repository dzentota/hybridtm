<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\RiskDecisionRecord;
use App\Entity\ThreatModelProject;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<RiskDecisionRecord>
 */
final class RiskDecisionRecordRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, RiskDecisionRecord::class);
    }

    /** @return list<RiskDecisionRecord> */
    public function findByProject(ThreatModelProject $project): array
    {
        return $this->findBy(['project' => $project]);
    }

    public function findByProjectAndFinding(ThreatModelProject $project, string $findingStableId): ?RiskDecisionRecord
    {
        return $this->findOneBy(['project' => $project, 'findingStableId' => $findingStableId]);
    }
}
