<?php
declare(strict_types=1);
namespace HybridTM\Kb\Rules;

use HybridTM\Analysis\Rules\RuleContext;
use HybridTM\Analysis\Rules\RuleInterface;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;

/**
 * Reference level-3 rule (§4.6): every strictly-confidential-handling
 * datastore must have a guard component (WAF, API gateway, reverse proxy,
 * IDS/IPS, ...) somewhere on every path an internet-facing asset can reach
 * it by. A path with no such guard within `config('max_hops')` edges is a
 * finding — this is exactly the kind of topology check a per-subject
 * `when`/`unless` expression cannot express.
 */
final class UnguardedPathFromInternetRule implements RuleInterface
{
    private const DEFAULT_GUARD_TRAITS = ['waf', 'api_gateway', 'reverse_proxy', 'ids', 'ips'];
    private const DEFAULT_MAX_HOPS = 4;

    public function evaluate(RuleContext $ctx): iterable
    {
        $guards = (array) $ctx->config('guard_traits', self::DEFAULT_GUARD_TRAITS);
        $maxHops = (int) $ctx->config('max_hops', self::DEFAULT_MAX_HOPS);

        foreach ($ctx->model->datastoresWithTrait('handles_strictly_confidential') as $datastore) {
            foreach ($ctx->graph->pathsFromInternet($datastore, $maxHops) as $path) {
                if ($path->anyNodeHasTrait(...$guards)) {
                    continue;
                }

                $finding = $ctx->raise(
                    threat: 'THREAT-UNGUARDED-DATASTORE-EXPOSURE',
                    subject: SubjectRef::component($datastore->id),
                    likelihood: Likelihood::VeryLikely,
                    impact: Impact::VeryHigh,
                    evidence: sprintf(
                        'Path from the internet to %s with no guarding component: %s',
                        $datastore->name,
                        $path->describe(),
                    ),
                    require: ['CM-WAF', 'CM-NETWORK-SEGMENTATION'],
                );

                if ($finding !== null) {
                    yield $finding;
                }
            }
        }
    }
}
