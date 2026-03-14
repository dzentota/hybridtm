<?php
declare(strict_types=1);
namespace HybridTM\Enums;

enum Protocol: string {
    case Unknown = 'unknown-protocol';
    case Http = 'http';
    case Https = 'https';
    case Ws = 'ws';
    case Wss = 'wss';
    case Mqtt = 'mqtt';
    case Jdbc = 'jdbc';
    case JdbcEncrypted = 'jdbc-encrypted';
    case Odbc = 'odbc';
    case OdbcEncrypted = 'odbc-encrypted';
    case SqlAccessProtocol = 'sql-access-protocol';
    case SqlAccessProtocolEncrypted = 'sql-access-protocol-encrypted';
    case NosqlAccessProtocol = 'nosql-access-protocol';
    case NosqlAccessProtocolEncrypted = 'nosql-access-protocol-encrypted';
    case Binary = 'binary';
    case BinaryEncrypted = 'binary-encrypted';
    case Text = 'text';
    case TextEncrypted = 'text-encrypted';
    case Ssh = 'ssh';
    case SshTunnel = 'ssh-tunnel';
    case Smtp = 'smtp';
    case SmtpEncrypted = 'smtp-encrypted';
    case Pop3 = 'pop3';
    case Pop3Encrypted = 'pop3-encrypted';
    case Imap = 'imap';
    case ImapEncrypted = 'imap-encrypted';
    case Ftp = 'ftp';
    case Ftps = 'ftps';
    case Sftp = 'sftp';
    case Scp = 'scp';
    case Nfs = 'nfs';
    case Smb = 'smb';
    case SmbEncrypted = 'smb-encrypted';
    case LocalFileAccess = 'local-file-access';
    case Ldap = 'ldap';
    case LdapEncrypted = 'ldap-encrypted';
    case InProcessLibraryCall = 'in-process-library-call';
    case ContainerSpawning = 'container-spawning';
}
