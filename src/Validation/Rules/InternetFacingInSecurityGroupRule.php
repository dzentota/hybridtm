<?php
declare(strict_types=1);
namespace HybridTM\Validation\Rules;

use HybridTM\Analysis\ModelIndex;
use HybridTM\Analysis\SubjectRef;
use HybridTM\DSL\ThreatModel;
use HybridTM\Enums\TrustBoundaryType;
use HybridTM\Kb\KnowledgeBaseInterface;
use HybridTM\Validation\RuleInterface;
use HybridTM\Validation\ValidationIssue;

/**
 * `internet: true` inside a `network-cloud-security-group` boundary is a
 * likely modeling mistake: a security group is a private network perimeter,
 * not something that fronts internet traffic directly (§3.6).
 */
final class InternetFacingInSecurityGroupRule implements RuleInterface
{
    public function code(): string
    {
        return 'validation/internet-facing-in-security-group';
    }

    public function check(ThreatModel $model, ?KnowledgeBaseInterface $kb): iterable
    {
        $index = ModelIndex::build($model);

        foreach ($model->getTechnicalAssets() as $assetId => $asset) {
            if (!$asset->internet) {
                continue;
            }

            $boundaryId = $index->boundaryOf($assetId);
            if ($boundaryId === null) {
                continue;
            }

            $boundary = $model->getTrustBoundaries()[$boundaryId];
            if ($boundary->type === TrustBoundaryType::NetworkCloudSecurityGroup) {
                yield ValidationIssue::warning(
                    $this->code(),
                    "Technical asset \"{$assetId}\" is marked internet-facing but sits inside "
                        . "security group \"{$boundaryId}\" — security groups are not internet perimeters.",
                    SubjectRef::component($assetId),
                );
            }
        }
    }
}
