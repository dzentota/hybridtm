<?php

declare(strict_types=1);

namespace HybridTM\Kb\Rules;

use HybridTM\Analysis\Rules\RuleContext;
use HybridTM\Analysis\Rules\RuleInterface;
use HybridTM\Analysis\SubjectRef;
use HybridTM\Enums\Impact;
use HybridTM\Enums\Likelihood;

/**
 * Generalizes `UnguardedPathFromInternetRule` from a single binary
 * "internet-facing" origin to every modeled Threat Actor: every strictly-
 * confidential-handling datastore must have a guard component somewhere on
 * every path a threat actor can reach it by, where reachability already
 * accounts for the actor's declared privilege level against the
 * authentication required on each intermediate link
 * (`RuleContextGraph::pathsFromThreatActors`). A path with no guard within
 * `config('max_hops')` edges is a finding.
 */
final class PathFromThreatActorRule implements RuleInterface
{
    private const DEFAULT_GUARD_TRAITS = ['waf', 'api_gateway', 'reverse_proxy', 'ids', 'ips'];
    private const DEFAULT_MAX_HOPS = 4;

    public function evaluate(RuleContext $ctx): iterable
    {
        $guards = (array) $ctx->config('guard_traits', self::DEFAULT_GUARD_TRAITS);
        $maxHops = (int) $ctx->config('max_hops', self::DEFAULT_MAX_HOPS);

        foreach ($ctx->model->datastoresWithTrait('handles_strictly_confidential') as $datastore) {
            foreach ($ctx->graph->pathsFromThreatActors($datastore, $maxHops) as $path) {
                if ($path->anyNodeHasTrait(...$guards)) {
                    continue;
                }

                $finding = $ctx->raise(
                    threat: 'THREAT-ACTOR-REACHABLE-DATASTORE',
                    subject: SubjectRef::component($datastore->id),
                    likelihood: Likelihood::VeryLikely,
                    impact: Impact::VeryHigh,
                    evidence: sprintf(
                        'Threat actor "%s" can reach %s with no guarding component: %s',
                        $path->originActorName() ?? 'unknown actor',
                        $datastore->name,
                        $path->describe(),
                    ),
                    require: ['CM-WAF-BLOCK-MODE', 'CM-NETWORK-SEGMENTATION'],
                );

                if ($finding !== null) {
                    yield $finding;
                }
            }
        }
    }
}
