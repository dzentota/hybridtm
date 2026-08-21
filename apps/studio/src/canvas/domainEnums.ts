/** Mirrors src/Enums/Protocol.php — the analyzer's `flow.protocol.isEncrypted()`
 * check matches these exact string values (Protocol::tryFrom), and silently
 * falls back to Https (encrypted, no findings) for anything that doesn't
 * match. A free-text field could send a string the backend can't parse and
 * would then wrongly read as "secure" — so this is a picker, not a text
 * input. Keep in sync with the PHP enum if it changes. */
export const PROTOCOLS: { value: string; label: string; encrypted: boolean }[] = [
  { value: 'unknown-protocol', label: 'Unknown', encrypted: false },
  { value: 'http', label: 'HTTP', encrypted: false },
  { value: 'https', label: 'HTTPS', encrypted: true },
  { value: 'ws', label: 'WebSocket', encrypted: false },
  { value: 'wss', label: 'WebSocket (TLS)', encrypted: true },
  { value: 'reverse-proxy-web-protocol', label: 'Reverse proxy (web)', encrypted: false },
  { value: 'reverse-proxy-web-protocol-encrypted', label: 'Reverse proxy (web, TLS)', encrypted: true },
  { value: 'mqtt', label: 'MQTT', encrypted: false },
  { value: 'jdbc', label: 'JDBC', encrypted: false },
  { value: 'jdbc-encrypted', label: 'JDBC (TLS)', encrypted: true },
  { value: 'odbc', label: 'ODBC', encrypted: false },
  { value: 'odbc-encrypted', label: 'ODBC (TLS)', encrypted: true },
  { value: 'sql-access-protocol', label: 'SQL access', encrypted: false },
  { value: 'sql-access-protocol-encrypted', label: 'SQL access (TLS)', encrypted: true },
  { value: 'nosql-access-protocol', label: 'NoSQL access', encrypted: false },
  { value: 'nosql-access-protocol-encrypted', label: 'NoSQL access (TLS)', encrypted: true },
  { value: 'binary', label: 'Binary', encrypted: false },
  { value: 'binary-encrypted', label: 'Binary (TLS)', encrypted: true },
  { value: 'text', label: 'Text', encrypted: false },
  { value: 'text-encrypted', label: 'Text (TLS)', encrypted: true },
  { value: 'ssh', label: 'SSH', encrypted: true },
  { value: 'ssh-tunnel', label: 'SSH tunnel', encrypted: true },
  { value: 'smtp', label: 'SMTP', encrypted: false },
  { value: 'smtp-encrypted', label: 'SMTP (TLS)', encrypted: true },
  { value: 'pop3', label: 'POP3', encrypted: false },
  { value: 'pop3-encrypted', label: 'POP3 (TLS)', encrypted: true },
  { value: 'imap', label: 'IMAP', encrypted: false },
  { value: 'imap-encrypted', label: 'IMAP (TLS)', encrypted: true },
  { value: 'ftp', label: 'FTP', encrypted: false },
  { value: 'ftps', label: 'FTPS', encrypted: true },
  { value: 'sftp', label: 'SFTP', encrypted: true },
  { value: 'scp', label: 'SCP', encrypted: true },
  { value: 'ldap', label: 'LDAP', encrypted: false },
  { value: 'ldaps', label: 'LDAPS', encrypted: true },
  { value: 'jms', label: 'JMS', encrypted: false },
  { value: 'nfs', label: 'NFS', encrypted: false },
  { value: 'smb', label: 'SMB', encrypted: false },
  { value: 'smb-encrypted', label: 'SMB (encrypted)', encrypted: true },
  { value: 'local-file-access', label: 'Local file access', encrypted: false },
  { value: 'nrpe', label: 'NRPE', encrypted: false },
  { value: 'xmpp', label: 'XMPP', encrypted: false },
  { value: 'iiop', label: 'IIOP', encrypted: false },
  { value: 'iiop-encrypted', label: 'IIOP (encrypted)', encrypted: true },
  { value: 'jrmp', label: 'JRMP', encrypted: false },
  { value: 'jrmp-encrypted', label: 'JRMP (encrypted)', encrypted: true },
  { value: 'in-process-library-call', label: 'In-process call', encrypted: true },
  { value: 'container-spawning', label: 'Container spawning', encrypted: false },
]

/** Mirrors src/Enums/TrustBoundaryType.php. */
export const BOUNDARY_TYPES: { value: string; label: string }[] = [
  { value: 'internet', label: 'Internet' },
  { value: 'network-on-prem', label: 'On-prem network' },
  { value: 'network-dedicated-hoster', label: 'Dedicated hoster network' },
  { value: 'network-virtual-lan', label: 'Virtual LAN' },
  { value: 'network-cloud-provider', label: 'Cloud provider network' },
  { value: 'network-cloud-security-group', label: 'Cloud security group' },
  { value: 'network-policy-namespace-isolation', label: 'Namespace isolation (network policy)' },
  { value: 'execution-environment', label: 'Execution environment' },
]

/** Mirrors src/Enums/Confidentiality.php — used to classify a data asset
 * (e.g. "Payment card data" → Restricted or Confidential, matching PCI-DSS
 * expectations). Declaration order matches the enum's own sensitivity rank. */
export const DATA_CLASSIFICATIONS: { value: string; label: string }[] = [
  { value: 'public', label: 'Public' },
  { value: 'internal', label: 'Internal' },
  { value: 'restricted', label: 'Restricted' },
  { value: 'confidential', label: 'Confidential' },
  { value: 'strictly-confidential', label: 'Strictly confidential' },
]
