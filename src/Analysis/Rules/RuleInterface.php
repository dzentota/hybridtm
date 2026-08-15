<?php
declare(strict_types=1);
namespace HybridTM\Analysis\Rules;

use HybridTM\Analysis\Finding;

/**
 * Level-3 KB rule (§4.6): a PHP class referenced by a `Rule` entity's
 * `spec.impl`, for the ~15% of rules that need real graph algorithms
 * (path-finding, reachability with guards) rather than a per-subject
 * `when`/`unless` expression.
 *
 * Unlike declarative rule expressions, implementations of this interface
 * are NOT sandboxed (ADR-05 only constrains the expression language) —
 * they are first-party or KB-vendor PHP code, reviewed like any other
 * code that ships in a Knowledge Base package.
 */
interface RuleInterface
{
    /** @return iterable<Finding> */
    public function evaluate(RuleContext $ctx): iterable;
}
