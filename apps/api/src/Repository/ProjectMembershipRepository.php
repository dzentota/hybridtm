<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\ProjectMembership;
use App\Entity\ThreatModelProject;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<ProjectMembership>
 */
final class ProjectMembershipRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, ProjectMembership::class);
    }

    public function findForUserAndProject(User $user, ThreatModelProject $project): ?ProjectMembership
    {
        return $this->findOneBy(['user' => $user, 'project' => $project]);
    }
}
