<?php

declare(strict_types=1);

namespace HybridTM\Enums;

/** Protocol values as accepted by Threagile 1.x (-list-types). */
enum Protocol: string
{
    case Unknown = 'unknown-protocol';
    case Http = 'http';
    case Https = 'https';
    case Ws = 'ws';
    case Wss = 'wss';
    case ReverseProxyWebProtocol = 'reverse-proxy-web-protocol';
    case ReverseProxyWebProtocolEncrypted = 'reverse-proxy-web-protocol-encrypted';
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
    case Ldap = 'ldap';
    case Ldaps = 'ldaps';
    case Jms = 'jms';
    case Nfs = 'nfs';
    case Smb = 'smb';
    case SmbEncrypted = 'smb-encrypted';
    case LocalFileAccess = 'local-file-access';
    case Nrpe = 'nrpe';
    case Xmpp = 'xmpp';
    case Iiop = 'iiop';
    case IiopEncrypted = 'iiop-encrypted';
    case Jrmp = 'jrmp';
    case JrmpEncrypted = 'jrmp-encrypted';
    case InProcessLibraryCall = 'in-process-library-call';
    case ContainerSpawning = 'container-spawning';

    /**
     * True for protocols that are encrypted in transit, either by an
     * explicit "-encrypted" variant or because the protocol itself implies
     * encryption (TLS-wrapped or SSH-based). Deliberately an exhaustive
     * match rather than a name-suffix heuristic: several unencrypted
     * protocols ('nfs', 'jms') happen to end in 's' too.
     */
    public function isEncrypted(): bool
    {
        return match ($this) {
            self::Https, self::Wss,
            self::ReverseProxyWebProtocolEncrypted,
            self::JdbcEncrypted, self::OdbcEncrypted,
            self::SqlAccessProtocolEncrypted, self::NosqlAccessProtocolEncrypted,
            self::BinaryEncrypted, self::TextEncrypted,
            self::SmtpEncrypted, self::Pop3Encrypted, self::ImapEncrypted,
            self::SmbEncrypted, self::IiopEncrypted, self::JrmpEncrypted,
            self::Ssh, self::SshTunnel, self::Ftps, self::Sftp, self::Scp, self::Ldaps => true,
            default => false,
        };
    }
}
