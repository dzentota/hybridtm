<?php

declare(strict_types=1);

namespace HybridTM\Analysis\Rules;

/**
 * Instantiates a `spec.impl` class reference from KB YAML. The class must
 * already be autoloadable — this loader does not read files itself, it
 * trusts Composer's autoloader (or whatever a consuming project wires up
 * for its own KB packages).
 */
final class PhpRuleLoader
{
    public function load(string $className): RuleInterface
    {
        if (!class_exists($className)) {
            throw new PhpRuleLoadException("Class \"{$className}\" referenced by spec.impl does not exist or is not autoloadable.");
        }

        if (!is_a($className, RuleInterface::class, true)) {
            throw new PhpRuleLoadException("Class \"{$className}\" does not implement " . RuleInterface::class . '.');
        }

        return new $className();
    }
}
