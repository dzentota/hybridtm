<?php

declare(strict_types=1);

namespace App\Entity;

/**
 * Model approval workflow (T-9.6): Draft -> InReview -> Approved ->
 * Superseded. An Approved version is immutable (ModelVersion's PUT
 * operation is blocked once status reaches Approved/Superseded) —
 * editing one means creating a brand-new ModelVersion instead, which
 * always starts life as Draft.
 */
enum ModelVersionStatus: string
{
    case Draft = 'draft';
    case InReview = 'in_review';
    case Approved = 'approved';
    case Superseded = 'superseded';

    public function isImmutable(): bool
    {
        return $this === self::Approved || $this === self::Superseded;
    }
}
