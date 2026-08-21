<?php

declare(strict_types=1);

namespace App\Validator;

use App\Entity\RiskDecisionRecord;
use HybridTM\Enums\DecisionStatus;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;
use Symfony\Component\Validator\Exception\UnexpectedValueException;

final class ValidRiskDecisionValidator extends ConstraintValidator
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof ValidRiskDecision) {
            throw new UnexpectedTypeException($constraint, ValidRiskDecision::class);
        }
        if (!$value instanceof RiskDecisionRecord) {
            throw new UnexpectedValueException($value, RiskDecisionRecord::class);
        }

        $status = DecisionStatus::tryFrom($value->status);
        if ($status?->requiresExpiry() && $value->expiresAt === null) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('{{ status }}', $value->status)
                ->atPath('expiresAt')
                ->addViolation();
        }
    }
}
