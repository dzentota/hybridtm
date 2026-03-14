<?php
declare(strict_types=1);
namespace HybridTM\Compiler;

use HybridTM\Enums\Authentication;
use HybridTM\Enums\Authorization;
use HybridTM\Enums\MitigationStatus;
use HybridTM\Enums\Protocol;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

final class DataFlowVisitor extends NodeVisitorAbstract
{
    /** @var DiscoveredDataFlow[] */
    private array $dataFlows = [];

    /** @var DiscoveredMitigation[] */
    private array $mitigations = [];

    /** @var DiscoveredProcessesData[] */
    private array $processesData = [];

    /** @var string[] */
    public array $warnings = [];

    private string $currentClass = '';
    private string $sourceAssetId = '';

    public function enterNode(Node $node): null
    {
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClass = (string) ($node->namespacedName ?? $node->name ?? '');
            foreach ($node->attrGroups as $attrGroup) {
                foreach ($attrGroup->attrs as $attr) {
                    $attrName = implode('\\', $attr->name->getParts());
                    if ($this->isAttr($attrName, 'ProcessesData')) {
                        $args = $this->extractArgs($attr->args);
                        $dataAssets = $args['dataAssets'] ?? $args[0] ?? [];
                        $this->processesData[] = new DiscoveredProcessesData(
                            dataAssets: is_array($dataAssets) ? $dataAssets : [$dataAssets],
                            context: $this->currentClass,
                        );
                    }
                    if ($this->isAttr($attrName, 'AssetId')) {
                        $args = $this->extractArgs($attr->args);
                        $this->sourceAssetId = (string) ($args[0] ?? $args['id'] ?? '');
                    }
                }
            }
        }

        if ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_) {
            $methodName = (string) ($node->name ?? '');
            $context = $this->currentClass !== '' ? $this->currentClass . '::' . $methodName : $methodName;

            foreach ($node->attrGroups as $attrGroup) {
                foreach ($attrGroup->attrs as $attr) {
                    $attrName = implode('\\', $attr->name->getParts());

                    if ($this->isAttr($attrName, 'DataFlow')) {
                        $this->handleDataFlow($attr, $context);
                    }

                    if ($this->isAttr($attrName, 'Mitigation')) {
                        $this->handleMitigation($attr, $context);
                    }

                    if ($this->isAttr($attrName, 'ProcessesData')) {
                        $args = $this->extractArgs($attr->args);
                        $dataAssets = $args['dataAssets'] ?? $args[0] ?? [];
                        $this->processesData[] = new DiscoveredProcessesData(
                            dataAssets: is_array($dataAssets) ? $dataAssets : [$dataAssets],
                            context: $context,
                        );
                    }
                }
            }
        }

        return null;
    }

    public function leaveNode(Node $node): null
    {
        if ($node instanceof Node\Stmt\Class_) {
            $this->currentClass = '';
            $this->sourceAssetId = '';
        }
        return null;
    }

    public function getResult(): AstResult
    {
        return new AstResult($this->dataFlows, $this->mitigations, $this->processesData, $this->warnings);
    }

    private function handleDataFlow(Node\Attribute $attr, string $context): void
    {
        $args = $this->extractArgs($attr->args);

        $target = (string) ($args['target'] ?? $args[0] ?? '');
        if ($target === '') {
            $this->warnings[] = "[DataFlow@{$context}] Missing required 'target' argument.";
            return;
        }

        $protocolRaw = $args['protocol'] ?? Protocol::Https;
        $protocol = $protocolRaw instanceof Protocol ? $protocolRaw : Protocol::tryFrom((string)$protocolRaw) ?? Protocol::Https;

        $authRaw = $args['authentication'] ?? Authentication::None;
        $auth = $authRaw instanceof Authentication ? $authRaw : Authentication::tryFrom((string)$authRaw) ?? Authentication::None;

        $authzRaw = $args['authorization'] ?? Authorization::None;
        $authz = $authzRaw instanceof Authorization ? $authzRaw : Authorization::tryFrom((string)$authzRaw) ?? Authorization::None;

        $dataSent = (array) ($args['dataSent'] ?? []);
        $dataReceived = (array) ($args['dataReceived'] ?? []);

        $this->dataFlows[] = new DiscoveredDataFlow(
            sourceAssetId: $this->sourceAssetId,
            targetAssetId: $target,
            protocol: $protocol,
            authentication: $auth,
            authorization: $authz,
            dataSent: $dataSent,
            dataReceived: $dataReceived,
            vpn: (bool) ($args['vpn'] ?? false),
            ipFiltered: (bool) ($args['ipFiltered'] ?? false),
            readonly: (bool) ($args['readonly'] ?? false),
            context: $context,
        );
    }

    private function handleMitigation(Node\Attribute $attr, string $context): void
    {
        $args = $this->extractArgs($attr->args);
        $cwe = (string) ($args['cwe'] ?? $args[0] ?? '');
        $description = (string) ($args['description'] ?? $args[1] ?? '');
        $statusRaw = $args['status'] ?? MitigationStatus::Mitigated;
        $status = $statusRaw instanceof MitigationStatus ? $statusRaw : MitigationStatus::tryFrom((string)$statusRaw) ?? MitigationStatus::Mitigated;

        $this->mitigations[] = new DiscoveredMitigation($cwe, $description, $status, $context);
    }

    /** @param Node\Arg[] $argNodes */
    private function extractArgs(array $argNodes): array
    {
        $result = [];
        foreach ($argNodes as $i => $arg) {
            $key = $arg->name ? $arg->name->name : $i;
            $result[$key] = $this->resolveValue($arg->value);
        }
        return $result;
    }

    private function resolveValue(Node\Expr $expr): mixed
    {
        return match (true) {
            $expr instanceof Node\Scalar\String_       => $expr->value,
            $expr instanceof Node\Scalar\LNumber       => $expr->value,
            $expr instanceof Node\Scalar\DNumber       => $expr->value,
            $expr instanceof Node\Expr\ConstFetch      => match(strtolower($expr->name->toString())) {
                'true' => true, 'false' => false, 'null' => null, default => $expr->name->toString(),
            },
            $expr instanceof Node\Expr\Array_          => $this->resolveArray($expr),
            $expr instanceof Node\Expr\ClassConstFetch => $this->resolveClassConst($expr),
            default                                     => null,
        };
    }

    private function resolveArray(Node\Expr\Array_ $arr): array
    {
        $result = [];
        foreach ($arr->items as $item) {
            if ($item === null) continue;
            $value = $this->resolveValue($item->value);
            if ($item->key !== null) {
                $result[$this->resolveValue($item->key)] = $value;
            } else {
                $result[] = $value;
            }
        }
        return $result;
    }

    private function resolveClassConst(Node\Expr\ClassConstFetch $expr): mixed
    {
        $class = $expr->class instanceof Node\Name ? $expr->class->toString() : '';
        $const = $expr->name instanceof Node\Identifier ? $expr->name->name : '';

        $enumMap = [
            'Protocol'         => Protocol::class,
            'Authentication'   => Authentication::class,
            'Authorization'    => Authorization::class,
            'MitigationStatus' => MitigationStatus::class,
        ];

        foreach ($enumMap as $shortName => $fqn) {
            if (str_ends_with($class, $shortName) || $class === $fqn) {
                $value = constant($fqn . '::' . $const);
                return $value;
            }
        }

        return $class . '::' . $const;
    }

    private function isAttr(string $attrName, string $shortName): bool
    {
        return $attrName === $shortName
            || $attrName === 'HybridTM\\Attributes\\' . $shortName
            || str_ends_with($attrName, '\\' . $shortName);
    }
}
