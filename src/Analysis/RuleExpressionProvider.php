<?php
declare(strict_types=1);
namespace HybridTM\Analysis;

use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

/**
 * Sandboxed evaluation of KB rule condition/template expressions (T-3.2).
 *
 * The "sandbox" is structural, not a runtime interceptor (ADR-05): this
 * class registers zero custom functions, so an expression can only read
 * properties and call methods on whatever context variables the caller
 * passes in — `component`, `flow`, `boundary` or `model`, always one of the
 * `Subjects\*` wrapper classes. Those wrappers' public surface *is* the
 * whitelist: there is no file, network or clock access reachable from a
 * rule expression because none of the Subject classes expose any.
 *
 * `Symfony\Component\ExpressionLanguage\ExpressionLanguage` compiles and
 * caches parsed expressions internally for the lifetime of the instance
 * (T-3.3) — construct one `RuleExpressionProvider` per `RuleEngine` and
 * reuse it across `analyze()` calls to avoid re-parsing the same rule
 * expressions on every run.
 */
final class RuleExpressionProvider
{
    private ExpressionLanguage $language;

    public function __construct()
    {
        $this->language = new ExpressionLanguage();
    }

    /**
     * @param array<string, mixed> $context
     * @throws RuleExpressionException if the expression is malformed or throws while evaluating
     */
    public function evaluate(string $expression, array $context): mixed
    {
        try {
            return $this->language->evaluate($expression, $context);
        } catch (\Throwable $e) {
            throw new RuleExpressionException(
                sprintf('Failed to evaluate expression "%s": %s', $expression, $e->getMessage()),
                previous: $e,
            );
        }
    }

    /**
     * Renders `{{ expr }}` placeholders by evaluating `expr` through this
     * same sandboxed evaluator and substituting its string form. This is
     * deliberately not a general templating engine: no filters (`|join`),
     * no control structures — only what the expression language itself
     * evaluates. KB rule authors relying on Twig-style filters in
     * `evidence`/`impact` strings (as in the plan's illustrative YAML) are
     * not yet supported; write a plain expression or a literal instead.
     *
     * @param array<string, mixed> $context
     */
    public function render(string $template, array $context): string
    {
        return (string) preg_replace_callback(
            '/\{\{\s*(.*?)\s*\}\}/',
            function (array $matches) use ($context): string {
                $value = $this->evaluate($matches[1], $context);
                return is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
            },
            $template,
        );
    }
}
