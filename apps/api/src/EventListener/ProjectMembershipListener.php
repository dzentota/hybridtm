<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\ProjectMembership;
use App\Entity\ProjectRole;
use App\Entity\ThreatModelProject;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsDoctrineListener;
use Doctrine\ORM\Event\PostPersistEventArgs;
use Doctrine\ORM\Events;
use Symfony\Bundle\SecurityBundle\Security;

/**
 * Grants the creating user an Admin ProjectMembership the moment a new
 * ThreatModelProject is persisted (T-9.4) — otherwise a brand-new project
 * would have no memberships at all and its own creator couldn't do
 * anything with it under the project-scoped voter. A nested persist+flush
 * inside postPersist is a well-established Doctrine pattern for exactly
 * this "create a dependent row right after the row it depends on" case.
 */
#[AsDoctrineListener(event: Events::postPersist)]
final class ProjectMembershipListener
{
    public function __construct(private readonly Security $security)
    {
    }

    public function postPersist(PostPersistEventArgs $args): void
    {
        $project = $args->getObject();
        if (!$project instanceof ThreatModelProject) {
            return;
        }

        $user = $this->security->getUser();
        if (!$user instanceof User) {
            return;
        }

        $em = $args->getObjectManager();
        $membership = new ProjectMembership();
        $membership->project = $project;
        $membership->user = $user;
        $membership->role = ProjectRole::Admin;

        $em->persist($membership);
        $em->flush();
    }
}
