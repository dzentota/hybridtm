<?php

declare(strict_types=1);

namespace App\Entity;

/**
 * The 5-role model from the plan's §9.1 (T-9.4): Viewer (read), Modeler
 * (edit model content), Reviewer (risk decisions), KbAuthor (org KB —
 * no KB-authoring endpoint exists yet, so this only grants Viewer-level
 * project access for now), Admin (everything, including membership
 * management). Deliberately project-scoped, not group-inheriting — group
 * inheritance is real scope from T-9.4 this pass doesn't cover; see
 * ProjectMembership's docblock.
 */
enum ProjectRole: string
{
    case Viewer = 'viewer';
    case Modeler = 'modeler';
    case Reviewer = 'reviewer';
    case KbAuthor = 'kb_author';
    case Admin = 'admin';

    public function canViewProject(): bool
    {
        return true;
    }

    public function canEditModel(): bool
    {
        return $this === self::Modeler || $this === self::Admin;
    }

    public function canDecideRisk(): bool
    {
        return $this === self::Reviewer || $this === self::Admin;
    }

    public function canManageMembers(): bool
    {
        return $this === self::Admin;
    }

    public function canDeleteProject(): bool
    {
        return $this === self::Admin;
    }
}
