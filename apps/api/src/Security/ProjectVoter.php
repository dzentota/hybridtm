<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\ProjectMembership;
use App\Entity\ThreatModelProject;
use App\Entity\User;
use App\Repository\ProjectMembershipRepository;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Project-scoped authorization (T-9.4): a ROLE_ADMIN user (a tenant
 * administrator, distinct from a project's own Admin membership) is
 * granted everything; everyone else needs a ProjectMembership on the
 * specific project being accessed, checked against ProjectRole's
 * capability methods.
 */
final class ProjectVoter extends Voter
{
    private const ATTRIBUTES = [
        'PROJECT_VIEW',
        'PROJECT_EDIT_MODEL',
        'PROJECT_DECIDE_RISK',
        'PROJECT_MANAGE_MEMBERS',
        'PROJECT_DELETE',
    ];

    public function __construct(private readonly ProjectMembershipRepository $memberships)
    {
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return \in_array($attribute, self::ATTRIBUTES, true) && $subject instanceof ThreatModelProject;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        if (!$user instanceof User) {
            return false;
        }

        if (\in_array('ROLE_ADMIN', $user->getRoles(), true)) {
            return true;
        }

        /** @var ThreatModelProject $project */
        $project = $subject;
        $membership = $this->memberships->findForUserAndProject($user, $project);
        if ($membership === null) {
            return false;
        }

        return match ($attribute) {
            'PROJECT_VIEW' => $membership->role->canViewProject(),
            'PROJECT_EDIT_MODEL' => $membership->role->canEditModel(),
            'PROJECT_DECIDE_RISK' => $membership->role->canDecideRisk(),
            'PROJECT_MANAGE_MEMBERS' => $membership->role->canManageMembers(),
            'PROJECT_DELETE' => $membership->role->canDeleteProject(),
            default => false,
        };
    }
}
