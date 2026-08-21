<?php

declare(strict_types=1);

namespace HybridTM\Validation;

use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\ValidationSeverity;

/** One model-quality problem. Not a risk — a defect in the model itself. */
final readonly class ValidationIssue implements \JsonSerializable
{
    public function __construct(
        public ValidationSeverity $severity,
        public string $code,
        public string $message,
        public ?SubjectRef $subject = null,
        public string $hint = '',
    ) {
    }

    public static function error(string $code, string $message, ?SubjectRef $subject = null, string $hint = ''): self
    {
        return new self(ValidationSeverity::Error, $code, $message, $subject, $hint);
    }

    public static function warning(string $code, string $message, ?SubjectRef $subject = null, string $hint = ''): self
    {
        return new self(ValidationSeverity::Warning, $code, $message, $subject, $hint);
    }

    public static function info(string $code, string $message, ?SubjectRef $subject = null, string $hint = ''): self
    {
        return new self(ValidationSeverity::Info, $code, $message, $subject, $hint);
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'severity' => $this->severity->value,
            'code' => $this->code,
            'message' => $this->message,
            'subject' => $this->subject?->__toString(),
            'hint' => $this->hint,
        ];
    }
}
