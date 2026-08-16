<?php
declare(strict_types=1);
namespace HybridTM\Codec;

use HybridTM\DSL\CommunicationLink;
use HybridTM\DSL\DataAsset;
use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\AssetType;
use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\Availability;
use HybridTM\Enums\BusinessCriticality;
use HybridTM\Enums\Confidentiality;
use HybridTM\Enums\DataOrigin;
use HybridTM\Enums\DataUsage;
use HybridTM\Enums\Encryption;
use HybridTM\Enums\Integrity;
use HybridTM\Enums\Machine;
use HybridTM\Enums\Protocol;
use HybridTM\Enums\Quantity;
use HybridTM\Enums\Size;
use HybridTM\Enums\Technology;
use HybridTM\Enums\TrustBoundaryType;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;

/**
 * Walks the top-level statements of a parsed `threat-model.php` and
 * constructs a real `ThreatModel` from whatever matches ADR-08's
 * recognizable subset — never by `require`-ing the file (that would
 * execute arbitrary code; unsafe the moment this runs somewhere other
 * than a trusted CLI, per ADR-08), but by extracting literal constructor
 * arguments and property values from the AST and calling the DSL's real
 * constructors/setters with them directly.
 *
 * Anything outside the subset (loops, conditionals, function calls,
 * string concatenation, variable variables, ...) is recorded as a
 * `NonCanonicalConstruct` and otherwise skipped — the rest of the file is
 * still processed best-effort.
 */
final class DslVisitor
{
    private const ENUM_CLASSES = [
        'AssetType' => AssetType::class,
        'Authentication' => Authentication::class,
        'Authorization' => Authorization::class,
        'Availability' => Availability::class,
        'BusinessCriticality' => BusinessCriticality::class,
        'Confidentiality' => Confidentiality::class,
        'DataOrigin' => DataOrigin::class,
        'DataUsage' => DataUsage::class,
        'Encryption' => Encryption::class,
        'Integrity' => Integrity::class,
        'Machine' => Machine::class,
        'Protocol' => Protocol::class,
        'Quantity' => Quantity::class,
        'Size' => Size::class,
        'Technology' => Technology::class,
        'TrustBoundaryType' => TrustBoundaryType::class,
    ];

    private const CONSTRUCTIBLE_CLASSES = ['ThreatModel', 'TechnicalAsset', 'DataAsset', 'TrustBoundary'];

    private const WHITELISTED_METHODS = ['communicatesTo', 'addAssets', 'addTechnicalAsset', 'addDataAsset', 'addTrustBoundary'];

    /** @var array<string, object> variable name => tracked DSL object */
    private array $vars = [];

    private ?ThreatModel $model = null;

    /** @var list<NonCanonicalConstruct> */
    private array $nonCanonical = [];

    /** @param list<Node\Stmt> $stmts top-level statements */
    public function read(array $stmts): DslReadResult
    {
        foreach ($stmts as $stmt) {
            $this->visitStatement($stmt);
        }

        return new DslReadResult($this->model, $this->nonCanonical);
    }

    private function visitStatement(Stmt $stmt): void
    {
        if ($stmt instanceof Stmt\Declare_ || $stmt instanceof Stmt\Use_ || $stmt instanceof Stmt\Nop || $stmt instanceof Stmt\InlineHTML) {
            return;
        }

        if ($stmt instanceof Stmt\Return_) {
            if ($stmt->expr instanceof Expr\Variable && is_string($stmt->expr->name)) {
                $returned = $this->vars[$stmt->expr->name] ?? null;
                if ($returned instanceof ThreatModel) {
                    $this->model = $returned;
                    return;
                }
            }
            $this->reject($stmt, 'return statement does not return a tracked ThreatModel variable');
            return;
        }

        if ($stmt instanceof Stmt\Expression) {
            $this->visitExpression($stmt->expr, $stmt);
            return;
        }

        $this->reject($stmt, 'statement type ' . $stmt->getType() . ' is outside the recognizable subset');
    }

    private function visitExpression(Expr $expr, Node $context): void
    {
        if ($expr instanceof Expr\Assign) {
            $this->visitAssign($expr);
            return;
        }

        if ($expr instanceof Expr\MethodCall) {
            $this->visitBareMethodCall($expr);
            return;
        }

        if ($expr instanceof Expr\Include_) {
            // `require_once __DIR__ . '/vendor/autoload.php';` — a benign,
            // expected preamble in a file meant to also run standalone.
            // Irrelevant to model construction; not flagged.
            return;
        }

        $this->reject($context, 'expression type ' . $expr->getType() . ' is outside the recognizable subset');
    }

    private function visitAssign(Expr\Assign $assign): void
    {
        if ($assign->var instanceof Expr\PropertyFetch) {
            $this->visitPropertyAssign($assign->var, $assign->expr);
            return;
        }

        if (!($assign->var instanceof Expr\Variable) || !is_string($assign->var->name)) {
            $this->reject($assign, 'assignment target is not a simple variable or property');
            return;
        }
        $varName = $assign->var->name;

        if ($assign->expr instanceof Expr\New_) {
            $this->visitNew($varName, $assign->expr);
            return;
        }

        if ($assign->expr instanceof Expr\MethodCall) {
            $result = $this->callMethod($assign->expr);
            if ($result !== null) {
                $this->vars[$varName] = $result;
            }
            return;
        }

        $this->reject($assign, 'unsupported assignment right-hand side: ' . $assign->expr->getType());
    }

    /** `$var->prop = <literal|enum-case|array>;` */
    private function visitPropertyAssign(Expr\PropertyFetch $target, Expr $valueExpr): void
    {
        if (!($target->var instanceof Expr\Variable) || !is_string($target->var->name)) {
            $this->reject($target, 'property assignment target is not a simple variable');
            return;
        }
        $object = $this->vars[$target->var->name] ?? null;
        if ($object === null) {
            $this->reject($target, "property assignment on untracked variable \${$target->var->name}");
            return;
        }

        if (!($target->name instanceof Node\Identifier)) {
            $this->reject($target, 'dynamic property name');
            return;
        }
        $property = $target->name->toString();
        if (!property_exists($object, $property)) {
            // PHP itself would only raise a deprecation notice (not throw)
            // for an undeclared dynamic property, which the try/catch below
            // wouldn't catch — check explicitly so a typo'd property name is
            // recognized as non-canonical rather than silently accepted.
            $this->reject($target, "->{$property} is not a declared property of " . get_class($object));
            return;
        }

        $value = $this->resolveValue($valueExpr);
        if ($value === self::UNRESOLVABLE) {
            $this->reject($valueExpr, "value assigned to ->{$property} is not a literal, enum case, or array of those");
            return;
        }

        try {
            $object->{$property} = $value;
        } catch (\Throwable $e) {
            $this->reject($target, "assigning ->{$property} failed: " . $e->getMessage());
        }
    }

    private function visitNew(string $varName, Expr\New_ $new): void
    {
        if (!($new->class instanceof Node\Name)) {
            $this->reject($new, 'new expression with a dynamic class name');
            return;
        }

        $className = $new->class->getLast();
        if (!in_array($className, self::CONSTRUCTIBLE_CLASSES, true)) {
            $this->reject($new, "new {$className}(...) is not a recognizable DSL entity constructor");
            return;
        }

        $args = $this->resolveArgs($new->args, $new);
        if ($args === null) {
            return;
        }

        try {
            $this->vars[$varName] = match ($className) {
                'ThreatModel' => new ThreatModel((string) ($args['title'] ?? $args[0] ?? '')),
                'TechnicalAsset' => new TechnicalAsset((string) ($args['id'] ?? $args[0] ?? ''), (string) ($args['name'] ?? $args[1] ?? '')),
                'DataAsset' => new DataAsset((string) ($args['id'] ?? $args[0] ?? ''), (string) ($args['name'] ?? $args[1] ?? '')),
                'TrustBoundary' => new TrustBoundary(
                    (string) ($args['id'] ?? $args[0] ?? ''),
                    (string) ($args['name'] ?? $args[1] ?? ''),
                    $args['type'] ?? $args[2] ?? TrustBoundaryType::NetworkOnPrem,
                ),
            };
        } catch (\Throwable $e) {
            $this->reject($new, "failed to construct {$className}: " . $e->getMessage());
        }
    }

    private function visitBareMethodCall(Expr\MethodCall $call): void
    {
        $this->callMethod($call);
    }

    /** Calls a whitelisted method on a tracked object; returns its result (for capture) or null. */
    private function callMethod(Expr\MethodCall $call): ?object
    {
        if (!($call->var instanceof Expr\Variable) || !is_string($call->var->name)) {
            $this->reject($call, 'method call target is not a simple variable');
            return null;
        }
        $target = $this->vars[$call->var->name] ?? null;
        if ($target === null) {
            $this->reject($call, "method call on untracked variable \${$call->var->name}");
            return null;
        }

        if (!($call->name instanceof Node\Identifier)) {
            $this->reject($call, 'dynamic method name');
            return null;
        }
        $method = $call->name->toString();
        if (!in_array($method, self::WHITELISTED_METHODS, true)) {
            $this->reject($call, "method ->{$method}(...) is not in the recognizable subset");
            return null;
        }

        // addTechnicalAsset/addDataAsset/addTrustBoundary take a tracked
        // object *variable*, not a literal — resolveArgs (which only
        // understands literals/enum-cases/arrays) must not run for them.
        if (in_array($method, ['addTechnicalAsset', 'addDataAsset', 'addTrustBoundary'], true)) {
            $arg = $call->args[0]->value ?? null;
            $resolved = $arg instanceof Expr\Variable && is_string($arg->name) ? ($this->vars[$arg->name] ?? null) : null;
            if ($resolved === null) {
                $this->reject($call, "->{$method}() argument is not a tracked variable");
                return null;
            }
            try {
                $target->{$method}($resolved);
            } catch (\Throwable $e) {
                $this->reject($call, "->{$method}(...) failed: " . $e->getMessage());
            }
            return null;
        }

        $args = $this->resolveArgs($call->args, $call);
        if ($args === null) {
            return null;
        }

        try {
            if ($method === 'addAssets') {
                $target->addAssets(...array_values($args));
                return null;
            }
            if ($method === 'communicatesTo') {
                return $target->communicatesTo(
                    targetId: (string) ($args['targetId'] ?? $args[0] ?? ''),
                    protocol: $args['protocol'] ?? Protocol::Https,
                    authentication: $args['authentication'] ?? Authentication::None,
                    authorization: $args['authorization'] ?? Authorization::None,
                    description: (string) ($args['description'] ?? ''),
                );
            }
        } catch (\Throwable $e) {
            $this->reject($call, "->{$method}(...) failed: " . $e->getMessage());
        }

        return null;
    }

    /**
     * @param list<Node\Arg> $args
     * @return array<int|string, mixed>|null null on failure (already recorded)
     */
    private function resolveArgs(array $args, Node $context): ?array
    {
        $result = [];
        foreach ($args as $i => $arg) {
            $value = $this->resolveValue($arg->value);
            if ($value === self::UNRESOLVABLE) {
                $this->reject($context, 'argument #' . ($i + 1) . ' is not a literal, enum case, or array of those');
                return null;
            }
            $key = $arg->name?->toString() ?? $i;
            $result[$key] = $value;
        }
        return $result;
    }

    private const UNRESOLVABLE = "\0unresolvable\0";

    private function resolveValue(Expr $expr): mixed
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $expr->value;
        }
        if ($expr instanceof Node\Scalar\LNumber || $expr instanceof Node\Scalar\Int_) {
            return $expr->value;
        }
        if ($expr instanceof Node\Scalar\DNumber || $expr instanceof Node\Scalar\Float_) {
            return $expr->value;
        }
        if ($expr instanceof Expr\ConstFetch) {
            return match (strtolower($expr->name->toString())) {
                'true' => true,
                'false' => false,
                'null' => null,
                default => self::UNRESOLVABLE,
            };
        }
        if ($expr instanceof Expr\Array_) {
            $items = [];
            foreach ($expr->items as $item) {
                if ($item === null) {
                    continue;
                }
                $value = $this->resolveValue($item->value);
                if ($value === self::UNRESOLVABLE) {
                    return self::UNRESOLVABLE;
                }
                if ($item->key !== null) {
                    $key = $this->resolveValue($item->key);
                    if ($key === self::UNRESOLVABLE) {
                        return self::UNRESOLVABLE;
                    }
                    $items[$key] = $value;
                } else {
                    $items[] = $value;
                }
            }
            return $items;
        }
        if ($expr instanceof Expr\ClassConstFetch) {
            return $this->resolveEnumCase($expr);
        }

        return self::UNRESOLVABLE;
    }

    private function resolveEnumCase(Expr\ClassConstFetch $expr): mixed
    {
        if (!($expr->class instanceof Node\Name) || !($expr->name instanceof Node\Identifier)) {
            return self::UNRESOLVABLE;
        }

        $shortName = $expr->class->getLast();
        $fqcn = self::ENUM_CLASSES[$shortName] ?? null;
        if ($fqcn === null) {
            return self::UNRESOLVABLE;
        }

        $caseName = $expr->name->toString();
        return constant("{$fqcn}::{$caseName}");
    }

    private function reject(Node $node, string $reason): void
    {
        $this->nonCanonical[] = new NonCanonicalConstruct($node->getStartLine(), $reason);
    }
}
