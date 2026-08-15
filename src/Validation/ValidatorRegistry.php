<?php
declare(strict_types=1);
namespace HybridTM\Validation;

use HybridTM\Validation\Rules\AssetInMultipleTrustBoundariesRule;
use HybridTM\Validation\Rules\AssetOutsideTrustBoundaryRule;
use HybridTM\Validation\Rules\CyclicTrustBoundaryNestingRule;
use HybridTM\Validation\Rules\DanglingCommunicationLinkTargetRule;
use HybridTM\Validation\Rules\DanglingDataAssetReferenceRule;
use HybridTM\Validation\Rules\DuplicateIdRule;
use HybridTM\Validation\Rules\InternetFacingInSecurityGroupRule;
use HybridTM\Validation\Rules\InvalidIdSlugRule;
use HybridTM\Validation\Rules\IsolatedDatastoreRule;
use HybridTM\Validation\Rules\PropertyNotInKbSchemaRule;
use HybridTM\Validation\Rules\UnknownKbComponentVersionRule;
use HybridTM\Validation\Rules\UnusedDataAssetRule;

/** Holds the set of model-quality checks a `ModelValidator` runs. */
final class ValidatorRegistry
{
    /** @var list<RuleInterface> */
    private array $rules = [];

    /** @param list<RuleInterface> $rules */
    public function __construct(array $rules = [])
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }
    }

    /** The 12 checks from §3.6, in dependency-free order. */
    public static function default(): self
    {
        return new self([
            new DanglingCommunicationLinkTargetRule(),
            new DanglingDataAssetReferenceRule(),
            new AssetInMultipleTrustBoundariesRule(),
            new CyclicTrustBoundaryNestingRule(),
            new DuplicateIdRule(),
            new InvalidIdSlugRule(),
            new IsolatedDatastoreRule(),
            new AssetOutsideTrustBoundaryRule(),
            new InternetFacingInSecurityGroupRule(),
            new PropertyNotInKbSchemaRule(),
            new UnusedDataAssetRule(),
            new UnknownKbComponentVersionRule(),
        ]);
    }

    public function add(RuleInterface $rule): static
    {
        $this->rules[] = $rule;
        return $this;
    }

    /** @return list<RuleInterface> */
    public function all(): array
    {
        return $this->rules;
    }
}
