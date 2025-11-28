# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AWS MCP Server, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send details to the repository maintainer (see GitHub profile)
2. **GitHub Security Advisory**: Use [GitHub's private vulnerability reporting](https://github.com/alexei-led/aws-mcp-server/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity (critical: ASAP, high: 30 days, medium: 90 days)

## Security Model

For detailed information about the security architecture, command validation, and sandbox execution, see [Security Architecture](docs/SECURITY.md).

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Security Best Practices

When using AWS MCP Server:

1. **Use Docker deployment** - Provides strongest isolation
2. **Apply least-privilege IAM** - Limit AWS credentials to minimum required permissions
3. **Keep updated** - Use latest version for security fixes
4. **Review blocked commands** - Understand what operations are restricted in strict mode
