"""Offline, conditional service guidance. Never vulnerability verification."""
import ipaddress

REVIEWED = '2026-11-17'
SOURCES = {
    'general': 'https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C_.pdf',
    'remote': 'https://www.ic3.gov/PSA/2018/PSA180927',
    'smb': 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic',
    'redis': 'https://redis.io/docs/latest/manual/security/',
    'postgres': 'https://www.postgresql.org/docs/current/auth-pg-hba-conf.html',
    'ssh': 'https://man.openbsd.org/sshd_config',
    'tls': 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
}
# Port hints are conventional associations, not observations of a protocol/version.
CATALOG = [
    ((22,), 'SSH', 'Review configuration',
     'If this is SSH, overly broad access or weak authentication can expose administrative access.',
     'Limit allowed users and source networks; review key-based authentication, root login and authentication policy without locking out administrators.', 'ssh'),
    ((139, 445), 'SMB / file sharing', 'Restrict access',
     'If this is file sharing, unnecessary network exposure can expand access to sensitive resources.',
     'Block direct internet SMB access; segment internal access to required clients and servers. Disable unused sharing.', 'smb'),
    ((3389,), 'RDP', 'Restrict access',
     'If this is RDP, broadly reachable remote administration needs strong access controls.',
     'Disable unused RDP; restrict source access, use a secured VPN/gateway, MFA where available, patching and login monitoring.', 'remote'),
    ((6379,), 'Redis', 'Restrict access',
     'If this is Redis, direct access by untrusted clients is outside its intended trust model.',
     'Restrict trusted clients with firewall and bind settings; review ACL authentication, protected mode and transport encryption.', 'redis'),
    ((5432,), 'PostgreSQL', 'Restrict access',
     'If this is PostgreSQL, broad host rules or trust authentication can permit unintended database access.',
     'Review pg_hba.conf for least-privilege host/user rules and appropriate authentication; do not use trust for untrusted clients.', 'postgres'),
    ((80, 8080), 'HTTP / web', 'Review configuration',
     'If this is HTTP, sensitive traffic may lack transport protection unless TLS is supplied elsewhere.',
     'Confirm the actual protocol and architecture; use TLS for sensitive traffic and review access controls and supported software.', 'tls'),
    ((443, 8443), 'HTTPS / TLS web', 'Review configuration',
     'If this is HTTPS, a port number alone does not establish TLS use, certificate validity or application security.',
     'Verify certificates, supported TLS configuration and application access controls using approved administrative checks.', 'tls'),
]
FALLBACK = ('Unidentified service', 'Identify service',
            'The application and its configuration are unknown; exposure alone does not prove a weakness.',
            'Identify the owning process/service through authorized administration. Disable it if unnecessary; otherwise restrict access and maintain updates.', 'general')


def context_for(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return 'Unclassified endpoint'
    if ip.is_loopback:
        return 'Loopback endpoint'
    if ip.is_global:
        return 'Globally addressed endpoint'
    return 'Non-global endpoint'


def assess(port, local=False, address=''):
    item = next((entry[1:] for entry in CATALOG if port in entry[0]), FALLBACK)
    service, priority, condition, recommendation, source = item
    if local:
        evidence = 'OS IPv4 listening-socket inventory only; no TCP connection attempted. Remote reachability is not assessed.'
        priority = 'Local review'
    else:
        evidence = 'TCP connection succeeded from this computer to the resolved endpoint at scan time. Reachability from other networks is not assessed.'
    return {
        'port': port, 'service_inference': service + ' (port-based guess)',
        'review_priority': priority, 'context': context_for(address),
        'evidence': evidence, 'confidence': 'Service identity: low; configuration and version: unknown.',
        'condition': condition, 'recommendation': recommendation,
        'vulnerabilities': 'Not assessed: no verified service/version, configuration checks or CVE matching.',
        'source': SOURCES[source], 'reviewed': REVIEWED,
    }
