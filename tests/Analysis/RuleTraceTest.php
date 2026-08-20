<?php

declare(strict_types=1);

namespace HybridTM\Tests\Analysis;

use HybridTM\Analysis\ConditionResult;
use HybridTM\Analysis\RuleTrace;
use PHPUnit\Framework\TestCase;

final class RuleTraceTest extends TestCase
{
    public function testDefaultsToNoConditionsAndNotMatched(): void
    {
        $trace = new RuleTrace('rule/x');

        self::assertSame('rule/x', $trace->ruleId);
        self::assertSame([], $trace->conditions);
        self::assertFalse($trace->matched);
        self::assertCount(0, $trace);
    }

    public function testCountReflectsNumberOfConditions(): void
    {
        $trace = new RuleTrace('rule/x', [
            new ConditionResult('a', true),
            new ConditionResult('b', false),
        ]);

        self::assertCount(2, $trace);
    }

    public function testFailedReturnsOnlyConditionsThatDidNotPass(): void
    {
        $passed = new ConditionResult('a == true', true);
        $failed = new ConditionResult('b == true', false);
        $trace = new RuleTrace('rule/x', [$passed, $failed]);

        self::assertSame([$failed], $trace->failed());
    }

    public function testFailedIsEmptyWhenAllConditionsPassed(): void
    {
        $trace = new RuleTrace('rule/x', [new ConditionResult('a', true)]);

        self::assertSame([], $trace->failed());
    }

    public function testSuppressedByReturnsOnlyPassedUnlessConditions(): void
    {
        $whenPassed = new ConditionResult('a', true, ConditionResult::KIND_WHEN);
        $unlessPassed = new ConditionResult('b', true, ConditionResult::KIND_UNLESS);
        $unlessFailed = new ConditionResult('c', false, ConditionResult::KIND_UNLESS);
        $trace = new RuleTrace('rule/x', [$whenPassed, $unlessPassed, $unlessFailed]);

        self::assertSame([$unlessPassed], $trace->suppressedBy());
    }

    public function testJsonSerializeIncludesRuleIdMatchedAndConditions(): void
    {
        $condition = new ConditionResult('a', true);
        $trace = new RuleTrace('rule/x', [$condition], true);

        self::assertSame([
            'ruleId' => 'rule/x',
            'matched' => true,
            'conditions' => [$condition],
        ], $trace->jsonSerialize());
    }
}
