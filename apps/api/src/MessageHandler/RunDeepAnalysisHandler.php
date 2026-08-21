<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Entity\DeepAnalysisResult;
use App\Entity\ModelVersion;
use App\Message\RunDeepAnalysis;
use Doctrine\ORM\EntityManagerInterface;
use HybridTM\Codec\ModelJsonCodec;
use HybridTM\Threagile\ThreagileRiskParser;
use HybridTM\Threagile\ThreagileRunException;
use HybridTM\Threagile\ThreagileRunnerInterface;
use HybridTM\Yaml\ThreagileSerializer;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Uid\Uuid;

/**
 * Handles `RunDeepAnalysis` off the request thread (T-6.5): compile the
 * stored model to Threagile YAML, run it through whichever
 * `ThreagileRunnerInterface` is configured (`NullThreagileRunner` unless a
 * deployment opts into Docker/Binary — see services.yaml), and store the
 * parsed findings back on the `DeepAnalysisResult` row the client is
 * polling/streaming.
 *
 * Uses the "admin" entity manager (T-9.1), not the request-scoped "app"
 * one: this worker has no authenticated Security user to derive a tenant
 * from, and it must look up a ModelVersion by id *before* it can know
 * which tenant's row-level-security session variable to set — a
 * chicken-and-egg the RLS-restricted connection can't resolve on its own.
 * It deliberately never calls `$em->getRepository(...)` or injects
 * `ModelVersionRepository`/`DeepAnalysisResultRepository`: those are
 * Symfony services, and `EntityManager::getRepository()` for a
 * service-backed repository resolves through Doctrine Bundle's
 * `ContainerRepositoryFactory`, which fetches the *shared service
 * instance* rather than one bound to this handler's entity manager. That
 * shared instance resolves its own manager via
 * `ManagerRegistry::getManagerForClass()`, which is ambiguous here (both
 * "app" and "admin" map the same entities) and deterministically picks
 * "app" — silently undoing the whole point of using "admin" here. Plain
 * `find()`/DQL against `$this->em` have no such indirection.
 */
#[AsMessageHandler]
final class RunDeepAnalysisHandler
{
    public function __construct(
        #[Autowire(service: 'doctrine.orm.admin_entity_manager')]
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
        $modelVersion = $this->em->find(ModelVersion::class, Uuid::fromString($message->modelVersionId));
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
        $existing = $this->em->createQuery(
            'SELECT d FROM App\Entity\DeepAnalysisResult d WHERE d.modelVersion = :mv ORDER BY d.createdAt DESC',
        )
            ->setParameter('mv', $modelVersion)
            ->setMaxResults(1)
            ->getOneOrNullResult();
        if ($existing !== null && !$existing->isTerminal()) {
            return $existing;
        }

        $result = new DeepAnalysisResult();
        $result->modelVersion = $modelVersion;
        $this->em->persist($result);

        return $result;
    }
}
