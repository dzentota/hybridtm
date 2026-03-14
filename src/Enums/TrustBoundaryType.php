<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum TrustBoundaryType: string {
    case NetworkOnPrem = 'network-on-prem';
    case NetworkDedicatedHoster = 'network-dedicated-hoster';
    case NetworkVirtualLan = 'network-virtual-lan';
    case NetworkCloudProvider = 'network-cloud-provider';
    case NetworkCloudSecurityGroup = 'network-cloud-security-group';
    case NetworkPolicyNamespaceIsolation = 'network-policy-namespace-isolation';
    case ExecutionEnvironment = 'execution-environment';
}
