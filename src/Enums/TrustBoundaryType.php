<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum TrustBoundaryType: string {
    /** The public internet — client devices sit here by default (outside
     * every other boundary), but modeling it as an explicit zone rather
     * than "not in any boundary" makes the untrusted side of the diagram
     * visible instead of implicit. */
    case Internet = 'internet';
    case NetworkOnPrem = 'network-on-prem';
    case NetworkDedicatedHoster = 'network-dedicated-hoster';
    case NetworkVirtualLan = 'network-virtual-lan';
    case NetworkCloudProvider = 'network-cloud-provider';
    case NetworkCloudSecurityGroup = 'network-cloud-security-group';
    case NetworkPolicyNamespaceIsolation = 'network-policy-namespace-isolation';
    case ExecutionEnvironment = 'execution-environment';
}
