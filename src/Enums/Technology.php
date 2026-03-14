<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Technology: string {
    case WebServiceRest = 'web-service-rest';
    case WebServiceSoap = 'web-service-soap';
    case WebApplication = 'web-application';
    case MobileApp = 'mobile-app';
    case Desktop = 'desktop-app';
    case Browser = 'browser';
    case CommandLine = 'command-line-interface';
    case Database = 'database';
    case FileServer = 'file-server';
    case LocalFileSystem = 'local-file-system';
    case Erp = 'erp';
    case Cms = 'cms';
    case WebApplicationFirewall = 'web-application-firewall';
    case ReverseProxy = 'reverse-proxy';
    case LoadBalancer = 'load-balancer';
    case BuildPipeline = 'build-pipeline';
    case SourcecodeRepository = 'sourcecode-repository';
    case ArtifactRegistry = 'artifact-registry';
    case CodeInspectionPlatform = 'code-inspection-platform';
    case Monitoring = 'monitoring';
    case LdapServer = 'ldap-server';
    case ContainerPlatform = 'container-platform';
    case BatchProcessing = 'batch-processing';
    case EventListener = 'event-listener';
    case StreamProcessing = 'stream-processing';
    case ServiceMesh = 'service-mesh';
    case DataLake = 'data-lake';
    case Unknown = 'unknown';
}
