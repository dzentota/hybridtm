<?php

declare(strict_types=1);

namespace HybridTM\Analysis\Subjects;

use HybridTM\DSL\ThreatModel;

/** The `model` variable exposed to model-scope rule expressions (§4.6). */
final readonly class ModelSubject
{
    public string $title;
    public string $businessCriticality;
    public int $technicalAssetCount;
    public int $trustBoundaryCount;

    public function __construct(private ThreatModel $model)
    {
        $this->title = $model->title;
        $this->businessCriticality = $model->businessCriticality->value;
        $this->technicalAssetCount = count($model->getTechnicalAssets());
        $this->trustBoundaryCount = count($model->getTrustBoundaries());
    }
}
