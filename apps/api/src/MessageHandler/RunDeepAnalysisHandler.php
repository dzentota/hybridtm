<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Entity\DeepAnalysisResult;
use App\Entity\ModelVersion;
use App\Message\RunDeepAnalysis;
use App\Repository\DeepAnalysisResultRepository;
use App\Repository\ModelVersionRepository;
use Doctrine\ORM\EntityManagerInterface;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Threagile\ThreagileRiskParser;
use HybridTM\Threagile\ThreagileRunException;
use HybridTM\Threagile\ThreagileRunnerInterface;
use HybridTM\Yaml\ThreagileSerializer;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Uid\Uuid;

/**
 * Handles `RunDeepAnalysis` off the request thread (T-6.5): compile the
 * stored model to Threagile YAML, run it through whichever
 * `ThreagileRunnerInterface` is configured (`NullThreagileRunner` unless a
 * deployment opts into Docker/Binary — see services.yaml), and store the
 * parsed findings back on the `DeepAnalysisResult` row the client is
 * polling/streaming.
 */
#[AsMessageHandler]
final class RunDeepAnalysisHandler
{
    public function __construct(
        private readonly ModelVersionRepository $modelVersions,
        private readonly DeepAnalysisResultRepository $results,
        private readonly EntityManagerInterface $em,
        private readonly ThreagileRunnerInterface $threagileRunner,
        private readonly ModelJsonCodec $codec,
        private readonly ThreagileSerializer $serializer,
        private readonly ThreagileRiskParser $riskParser,
        private readonly string $threagileWorkDir,
    ) {
    }

    public function __invoke(RunDeepAnalysis $message): void
    {
        $modelVersion = $this->modelVersions->find(Uuid::fromString($message->modelVersionId));
        if ($modelVersion === null) {
            return;
        }

        $result = $this->findOrCreateResult($modelVersion);
        $result->status = DeepAnalysisResult::STATUS_RUNNING;
        $this->em->flush();

        try {
            $findings = $this->runThreagile($modelVersion);
            $result->findings = array_map(
                static fn ($finding): array => $finding->jsonSerialize(),
                $findings,
            );
            $result->status = DeepAnalysisResult::STATUS_COMPLETED;
        } catch (\Throwable $e) {
            $result->status = DeepAnalysisResult::STATUS_FAILED;
            $result->error = $e->getMessage();
        }

        $result->completedAt = new \DateTimeImmutable();
        $this->em->flush();
    }

    /** @return list<\HybridTM\Analysis\Finding> */
    private function runThreagile(ModelVersion $modelVersion): array
    {
        $model = $this->codec->decode($modelVersion->data);
        $yaml = $this->serializer->serialize($model);

        $runDir = rtrim($this->threagileWorkDir, '/') . '/' . $modelVersion->getId()->toRfc4122();
        if (!is_dir($runDir) && !mkdir($runDir, 0775, true) && !is_dir($runDir)) {
            throw new ThreagileRunException("Could not create Threagile work directory: {$runDir}");
        }

        $yamlPath = $runDir . '/threagile.yaml';
        file_put_contents($yamlPath, $yaml);

        $runResult = $this->threagileRunner->run($yamlPath, $runDir);
        if (!$runResult->succeeded() || $runResult->risksJsonPath === null) {
            throw new ThreagileRunException('Threagile run did not produce risks.json: ' . $runResult->stderr);
        }

        return $this->riskParser->parseFile($runResult->risksJsonPath);
    }

    private function findOrCreateResult(ModelVersion $modelVersion): DeepAnalysisResult
    {
        $existing = $this->results->findOneBy(['modelVersion' => $modelVersion], ['createdAt' => 'DESC']);
        if ($existing !== null && !$existing->isTerminal()) {
            return $existing;
        }

        $result = new DeepAnalysisResult();
        $result->modelVersion = $modelVersion;
        $this->em->persist($result);

        return $result;
    }
}
