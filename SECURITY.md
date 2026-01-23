# Security Policy

USB Sentinel is a security-focused project. We take security vulnerabilities seriously and appreciate responsible disclosure.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: Send a detailed report to the project maintainers via GitHub private vulnerability reporting or through the repository's security advisory feature.

2. **GitHub Security Advisories**: Use the [Security Advisories](https://github.com/kase1111-hash/USB-Sentinel/security/advisories/new) feature to privately report vulnerabilities.

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., privilege escalation, policy bypass, LLM prompt injection)
- **Affected components** (e.g., interceptor, policy engine, analyzer, API)
- **Step-by-step reproduction instructions**
- **Proof of concept** (if available)
- **Impact assessment** - what an attacker could achieve
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30-90 days depending on severity

## Security Considerations

### Architecture Security

USB Sentinel implements defense-in-depth with these security boundaries:

| Layer | Security Constraint |
|-------|---------------------|
| Event Interceptor | Read-only USB access; no write operations |
| Policy Engine | No network access; deterministic evaluation |
| LLM Analyzer | Rate-limited; sandboxed prompt construction |
| Virtual Proxy | Isolated namespace; no host filesystem access |
| Audit System | Append-only database; tamper-evident logging |

### Known Attack Surfaces

1. **Policy Bypass**: Malicious devices attempting to evade rule matching
2. **LLM Prompt Injection**: Crafted device descriptors attempting to manipulate LLM output
3. **Privilege Escalation**: Exploiting daemon privileges for system access
4. **API Authentication Bypass**: Unauthorized access to management endpoints
5. **Audit Log Tampering**: Attempting to modify or delete audit records

### Security Best Practices

When deploying USB Sentinel:

- Run the daemon with minimal required privileges
- Use mTLS for API authentication in production
- Regularly review and update policy rules
- Monitor audit logs for anomalies
- Keep the software updated to the latest version

## Vulnerability Disclosure Policy

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. We confirm receipt and begin investigation
3. We develop and test a fix
4. We coordinate release timing with reporter
5. We publish security advisory and fix simultaneously
6. We credit reporter (unless they prefer anonymity)

## Security Updates

Security updates are released as patch versions (e.g., 0.1.1, 0.1.2). Critical vulnerabilities may trigger immediate releases.

Subscribe to repository releases to receive security update notifications.

## Acknowledgments

We maintain a list of security researchers who have responsibly disclosed vulnerabilities (with their permission) in our security advisories.

Thank you for helping keep USB Sentinel and its users secure.
