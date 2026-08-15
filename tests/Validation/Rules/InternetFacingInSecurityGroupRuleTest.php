<?php
declare(strict_types=1);
namespace HybridTM\Tests\Validation\Rules;

use HybridTM\DSL\TechnicalAsset;
use HybridTM\DSL\ThreatModel;
use HybridTM\DSL\TrustBoundary;
use HybridTM\Enums\TrustBoundaryType;
use HybridTM\Validation\Rules\InternetFacingInSecurityGroupRule;
use PHPUnit\Framework\TestCase;

final class InternetFacingInSecurityGroupRuleTest extends TestCase
{
    private InternetFacingInSecurityGroupRule $rule;

    protected function setUp(): void
    {
        $this->rule = new InternetFacingInSecurityGroupRule();
    }

    public function testFlagsInternetFacingAssetInSecurityGroup(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $model->addTechnicalAsset($web);
        $sg = new TrustBoundary('sg', type: TrustBoundaryType::NetworkCloudSecurityGroup);
        $sg->addAssets('web');
        $model->addTrustBoundary($sg);

        self::assertCount(1, iterator_to_array($this->rule->check($model, null)));
    }

    public function testPassesForNonInternetFacingAsset(): void
    {
        $model = new ThreatModel('App');
        $model->addTechnicalAsset(new TechnicalAsset('web'));
        $sg = new TrustBoundary('sg', type: TrustBoundaryType::NetworkCloudSecurityGroup);
        $sg->addAssets('web');
        $model->addTrustBoundary($sg);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }

    public function testPassesWhenInternetFacingButNotInSecurityGroup(): void
    {
        $model = new ThreatModel('App');
        $web = new TechnicalAsset('web');
        $web->internet = true;
        $model->addTechnicalAsset($web);
        $net = new TrustBoundary('net', type: TrustBoundaryType::NetworkOnPrem);
        $net->addAssets('web');
        $model->addTrustBoundary($net);

        self::assertSame([], iterator_to_array($this->rule->check($model, null)));
    }
}
