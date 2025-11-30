# Security Architecture

The AWS MCP Server implements a clear three-layer security model with separation of concerns.

## Security Model

```
Command → Sandbox → AWS CLI → IAM Policy → AWS Cloud
```

| Layer            | Responsibility      | What It Controls                        |
| ---------------- | ------------------- | --------------------------------------- |
| **IAM Policies** | AWS API permissions | What AWS operations succeed or fail     |
| **Sandbox**      | Process isolation   | Filesystem access, process restrictions |
| **Docker**       | Container isolation | Available binaries, attack surface      |

## Layer 1: IAM Policies (Primary Security)

**IAM is your primary security control.** The MCP server does not filter AWS commands - security is delegated to IAM policies.

The server executes AWS CLI commands using the credentials you provide (via mounted `~/.aws` or environment variables).

### Key Principles

- **Least Privilege**: Configure IAM with minimum necessary permissions
- **No Root Credentials**: Never use AWS account root user credentials
- **Scoped Permissions**: Use resource-based conditions when possible

### Example: Read-Only Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "ec2:Describe*",
        "cloudwatch:GetMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

With this policy, attempts to run `aws iam create-user` will return `AccessDenied`.

## Layer 2: Sandbox Execution

When running outside Docker, the server provides OS-level process isolation.

### Supported Backends

| Platform | Backend      | Requirements                       |
| -------- | ------------ | ---------------------------------- |
| Linux    | Landlock LSM | Kernel 5.13+ with Landlock enabled |
| Linux    | Bubblewrap   | `bwrap` installed (fallback)       |
| macOS    | Seatbelt     | Built-in (sandbox-exec)            |

### Configuration

| Variable                      | Values                         | Default |
| ----------------------------- | ------------------------------ | ------- |
| `AWS_MCP_SANDBOX`             | `auto`, `disabled`, `required` | `auto`  |
| `AWS_MCP_SANDBOX_CREDENTIALS` | `env`, `aws_config`, `both`    | `both`  |

### Sandbox Restrictions

- **Read-only access** to system paths (`/usr`, `/bin`, `/lib`, `/etc`)
- **Write access** limited to `/tmp` and current directory
- **Network access** enabled (required for AWS API calls)

## Layer 3: Docker Container

Docker provides the strongest isolation with a hardened container.

### Container Hardening

| Setting                  | Purpose                          |
| ------------------------ | -------------------------------- |
| `read_only: true`        | Read-only filesystem             |
| `tmpfs` mounts           | Writable `/tmp` with size limits |
| `no-new-privileges:true` | Prevents privilege escalation    |
| `cap_drop: ALL`          | Drops all Linux capabilities     |
| `pids_limit: 100`        | Prevents fork bomb attacks       |

### Minimal Image

The Docker image contains only essential packages:

- **Included**: AWS CLI, jq, basic text processing (grep, head, tail, sort, wc)
- **Excluded**: Debug tools, compilers, package managers

This minimal image limits what piped commands can execute.

### Volume Mounts

```yaml
volumes:
  - ~/.aws:/home/appuser/.aws:ro
```

Credentials are mounted read-only.

## Why No Application-Layer Command Filtering?

Previous versions attempted complex command filtering. This was removed because:

1. **Wrong Layer**: AWS permissions belong in IAM, not application code
2. **Inconsistent**: Piped commands bypassed filtering anyway
3. **False Security**: Pattern matching can be circumvented
4. **Maintenance Burden**: Keeping rules current is error-prone

The current model follows the principle: **use the right tool for each job**.

## Trusted User Model

The server assumes the end-user interacting with the MCP client is the same trusted individual who configured the server.

- Do not expose the server to untrusted users
- IAM policies are the defense against credential misuse

## Best Practices

1. **Use Docker** for production deployments
2. **Apply least-privilege IAM** - this is your primary security control
3. **Enable sandbox** when not using Docker
4. **Monitor CloudTrail** - track all API activity
5. **Regular IAM audits** - review permissions periodically

## Deployment

### Production (Docker)

```bash
docker compose up -d
```

Set `AWS_MCP_SANDBOX=disabled` - Docker provides isolation.

### Development (Native)

```bash
python -m aws_mcp_server

# Require sandbox
AWS_MCP_SANDBOX=required python -m aws_mcp_server
```
