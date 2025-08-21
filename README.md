# AWS Model Context Protocol (MCP) Server

[![CI](https://github.com/alexei-led/aws-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/alexei-led/aws-mcp-server/actions/workflows/ci.yml)
[![Code Coverage](https://codecov.io/gh/alexei-led/aws-mcp-server/branch/main/graph/badge.svg?token=K8vdP3zyuy)](https://codecov.io/gh/alexei-led/aws-mcp-server)
[![Linter: Ruff](https://img.shields.io/badge/Linter-Ruff-brightgreen?style=flat-square)](https://github.com/alexei-led/aws-mcp-server)
[![Image Tags](https://ghcr-badge.egpl.dev/alexei-led/aws-mcp-server/tags?color=%2344cc11&ignore=latest&n=4&label=image+tags&trim=)](https://github.com/alexei-led/aws-mcp-server/pkgs/container/aws-mcp-server/versions)
[![Image Size](https://ghcr-badge.egpl.dev/alexei-led/aws-mcp-server/size?color=%2344cc11&tag=latest&label=image+size&trim=)](https://github.com/alexei-led/aws-mcp-server/pkgs/container/aws-mcp-server)

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/alexei-led/aws-mcp-server)](https://archestra.ai/mcp-catalog/alexei-led__aws-mcp-server)

A lightweight service that enables AI assistants to execute AWS CLI commands through the Model Context Protocol (MCP).

## Overview

The AWS MCP Server provides a bridge between MCP-aware AI assistants (like Claude Desktop, Cursor, Windsurf) and the AWS CLI. It enables these assistants to:

1. **Retrieve AWS CLI documentation** (`aws_cli_help`) - Get detailed help on AWS services and commands
2. **Execute AWS CLI commands** (`aws_cli_pipeline`) - Run commands with Unix pipes and receive formatted results optimized for AI consumption

```mermaid
flowchart LR
    AI[AI Assistant] <-->|MCP Protocol| Server[AWS MCP Server]
    Server <-->|Subprocess| AWS[AWS CLI]
    AWS <-->|API| Cloud[AWS Cloud]
```

## Demo

[Demo](https://private-user-images.githubusercontent.com/1898375/424996801-b51ddc8e-5df5-40c4-8509-84c1a7800d62.mp4?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NDI0NzY5OTUsIm5iZiI6MTc0MjQ3NjY5NSwicGF0aCI6Ii8xODk4Mzc1LzQyNDk5NjgwMS1iNTFkZGM4ZS01ZGY1LTQwYzQtODUwOS04NGMxYTc4MDBkNjIubXA0P1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9QUtJQVZDT0RZTFNBNTNQUUs0WkElMkYyMDI1MDMyMCUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNTAzMjBUMTMxODE1WiZYLUFtei1FeHBpcmVzPTMwMCZYLUFtei1TaWduYXR1cmU9NjgwNTM4MDVjN2U4YjQzN2Y2N2Y5MGVkMThiZTgxYWEyNzBhZTlhMTRjZDY3ZDJmMzJkNmViM2U4M2U4MTEzNSZYLUFtei1TaWduZWRIZWFkZXJzPWhvc3QifQ.tIb7uSkDpSaspIluzCliHS8ATmlzkvEnF3CiClD-UGQ)

The video demonstrates using Claude Desktop with AWS MCP Server to create a new AWS EC2 instance with AWS SSM agent installed.

## Features

- **Command Documentation** - Detailed help information for AWS CLI commands
- **Command Execution** - Execute AWS CLI commands and return human-readable results
- **Unix Pipe Support** - Filter and transform AWS CLI output using standard Unix pipes and utilities
- **AWS Resources Context** - Access to AWS profiles, regions, account information, and environment details via MCP Resources
- **Prompt Templates** - Pre-defined prompt templates for common AWS tasks following best practices
- **Docker Integration** - Simple deployment through containerization with multi-architecture support (AMD64/x86_64 and ARM64)
- **AWS Authentication** - Leverages existing AWS credentials on the host machine

## Requirements

- Docker (default) or Python 3.13+ (and AWS CLI installed locally)
- AWS credentials configured

## Getting Started

**Note:** For security and reliability, running the server inside a Docker container is the **strongly recommended** method. Please review the [Security Considerations](#security-considerations) section for important considerations.

### Run Server Option 1: Using Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/alexei-led/aws-mcp-server.git
cd aws-mcp-server

# Build and run Docker container
docker compose -f deploy/docker/docker-compose.yml up -d
```

The Docker image supports both AMD64/x86_64 (Intel/AMD) and ARM64 (Apple Silicon M1-M4, AWS Graviton) architectures.

> **Note**: The official image from GitHub Packages is multi-architecture and will automatically use the appropriate version for your system.
>
> ```bash
> # Use the latest stable version
> docker pull ghcr.io/alexei-led/aws-mcp-server:latest
> 
> # Or pin to a specific version (recommended for production)
> docker pull ghcr.io/alexei-led/aws-mcp-server:1.0.0
> ```
>
> **Docker Image Tags**:
>
> - `latest`: Latest stable release
> - `x.y.z` (e.g., `1.0.0`): Specific version
> - `sha-<commit-sha>`: Development builds, tagged with Git commit SHA (e.g., `sha-gb697684`)

### Run Server Option 2: Using Python

**Use with Caution:** Running natively requires careful environment setup and carries higher security risks compared to the recommended Docker deployment. Ensure you understand the implications outlined in the [Security Considerations](#security-considerations) section.

```bash
# Clone repository
git clone https://github.com/alexei-led/aws-mcp-server.git
cd aws-mcp-server

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Run the server
python -m aws_mcp_server
```

## Configuration

The AWS MCP Server can be configured using environment variables:

| Environment Variable      | Description                                  | Default   |
|--------------------------|----------------------------------------------|-----------|
| `AWS_MCP_TIMEOUT`        | Command execution timeout in seconds         | 300       |
| `AWS_MCP_MAX_OUTPUT`     | Maximum output size in characters            | 100000    |
| `AWS_MCP_TRANSPORT`      | Transport protocol to use ("stdio" or "sse") | stdio     |
| `AWS_PROFILE`            | AWS profile to use                           | default   |
| `AWS_REGION`             | AWS region to use                            | us-east-1 |
| `AWS_MCP_SECURITY_MODE`  | Security mode ("strict" or "permissive")     | strict    |
| `AWS_MCP_SECURITY_CONFIG`| Path to custom security configuration file   | ""        |

**Important:** Securely manage the AWS credentials provided to the server, whether via mounted `~/.aws` files or environment variables. Ensure the credentials follow the principle of least privilege as detailed in the [Security Considerations](#security-considerations) section. When running via Docker, ensure these variables are passed correctly to the container environment (e.g., using `docker run -e VAR=value ...`).

## Security Considerations

Security is paramount when executing commands against your AWS environment. While AWS MCP Server provides functionality, **you are responsible** for configuring and running it securely. Please adhere strictly to the following:

**1. Recommended Deployment: Docker Container**

*   **Isolation:** Running the server inside a Docker container is the **strongly recommended and default** deployment method. Containerization provides crucial filesystem and process isolation. Potentially destructive Unix commands (like `rm`, `mv`) executed via pipes, even if misused, will be contained within the ephemeral Docker environment and will **not** affect your host machine's filesystem. The container can be easily stopped and recreated.
*   **Controlled Environment:** Docker ensures a consistent environment with necessary dependencies, reducing unexpected behavior.

**2. AWS Credentials and IAM Least Privilege (Critical)**

*   **User Responsibility:** You provide the AWS credentials to the server (via mounted `~/.aws` or environment variables).
*   **Least Privilege is Essential:** The server executes AWS CLI commands *using the credentials you provide*. It is **absolutely critical** that these credentials belong to an IAM principal (User or Role) configured with the **minimum necessary permissions** (least privilege) for *only* the AWS actions you intend to perform through this tool.
    *   **Do Not Use Root Credentials:** Never use AWS account root user credentials.
    *   **Regularly Review Permissions:** Periodically audit the IAM permissions associated with the credentials.
*   **Impact Limitation:** Properly configured IAM permissions are the **primary mechanism** for limiting the potential impact of *any* command executed via the server, whether intended or unintended. Even if a command were manipulated, it could only perform actions allowed by the specific IAM policy.

**3. Trusted User Model**

*   The server assumes the end-user interacting with the MCP client (e.g., Claude Desktop, Cursor) is the **same trusted individual** who configured the server and provided the least-privilege AWS credentials. Do not expose the server or connected client to untrusted users.

**4. Understanding Execution Risks (Current Implementation)**

*   **Command Execution:** The current implementation uses shell features (`shell=True` in subprocess calls) to execute AWS commands and handle Unix pipes. While convenient, this approach carries inherent risks if the input command string were manipulated (command injection).
*   **Mitigation via Operational Controls:** In the context of the **trusted user model** and **Docker deployment**, these risks are mitigated operationally:
    *   The trusted user is assumed not to provide intentionally malicious commands against their own environment.
    *   Docker contains filesystem side-effects.
    *   **Crucially, IAM least privilege limits the scope of *any* AWS action that could be executed.**
*   **Credential Exfiltration Risk:** Despite containerization and IAM, a sophisticated command injection could potentially attempt to read the mounted credentials (`~/.aws`) or environment variables within the container and exfiltrate them (e.g., via `curl`). **Strict IAM policies remain the most vital defense** to limit the value of potentially exfiltrated credentials.

**5. Network Exposure (SSE Transport)**

*   If using the `sse` transport (which implies a network listener), ensure you bind the server only to trusted network interfaces (e.g., `localhost`) or implement appropriate network security controls (firewalls, authentication proxies) if exposing it more broadly. The default `stdio` transport does not open network ports.

**6. Shared Responsibility Summary**

*   **AWS MCP Server provides the tool.**
*   **You, the user, are responsible for:**
    *   Running it within the recommended secure Docker environment.
    *   Providing and securely managing **least-privilege** AWS credentials.
    *   Ensuring only trusted users interact with the server/client.
    *   Securing the network environment if applicable.

By strictly adhering to Docker deployment and meticulous IAM least-privilege configuration, you establish the necessary operational controls for using the AWS MCP Server securely with its current implementation.

## Integrating with Claude Desktop

### Configuration

To manually integrate AWS MCP Server with Claude Desktop:

1. **Locate the Claude Desktop configuration file**:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. **Edit the configuration file** to include the AWS MCP Server:
   ```json
   {
     "mcpServers": {
       "aws-mcp-server": {
         "command": "docker",
         "args": [
           "run",
           "-i",
           "--rm",
           "-v",
           "/Users/YOUR_USER_NAME/.aws:/home/appuser/.aws:ro",
           "ghcr.io/alexei-led/aws-mcp-server:latest"
         ]
       }
     }
   }
   ```
   
3. **Restart Claude Desktop** to apply the changes
   - After restarting, you should see a hammer 🔨 icon in the bottom right corner of the input box
   - This indicates that the AWS MCP Server is available for use

```mermaid
flowchart TD
    subgraph "User Device"
        config[Edit claude_desktop_config.json]
        claude[Claude Desktop]
        docker[Docker Container]
        aws_creds[AWS Credentials]
    end
    
    subgraph "AWS Cloud"
        services[AWS Services]
    end
    
    subgraph "MCP Server Components"
        tools[AWS CLI Tools]
        resources[AWS Resources]
        templates[Prompt Templates]
    end
    
    config -->|Add MCP Server Config| claude
    claude -->|Docker Run Command| docker
    docker --- tools
    docker --- resources
    docker --- templates
    aws_creds -->|Mount Read-only| docker
    resources -.->|Read| aws_creds
    tools -->|API Calls| services
```

### Example Interactions

**Getting AWS CLI Documentation**:
```
User: What are the available options for the AWS S3 cp command?

Claude: Let me get that information for you.

The AWS S3 cp command has the following options:

NAME
    cp - Copies a local file or S3 object to another location locally or in S3.

SYNOPSIS
    cp <LocalPath> <S3Uri> or <S3Uri> <LocalPath> or <S3Uri> <S3Uri> [--acl <value>] [--cache-control <value>] ...
```

**Executing AWS CLI Commands**:
```
User: List my S3 buckets

Claude: I'll list your S3 buckets for you.

2023-10-15 14:30:45 my-bucket-1
2023-11-20 09:15:32 my-bucket-2
2024-01-05 11:22:18 my-backup-bucket
```

**Using Command Pipes**:
```
User: List my S3 buckets that have "backup" in their name and show them in alphabetical order

Claude: Let me find that for you.

2024-01-05 11:22:18 my-backup-bucket
2024-03-01 09:44:12 weekly-backup-bucket
2024-03-15 13:10:57 database-backup-bucket
```

**Accessing AWS Resources**:
```
User: What AWS regions are available for me to use?

Claude: Let me check what AWS regions are available for you.

Available regions:
- us-east-1 (US East, N. Virginia) - Currently selected
- us-east-2 (US East, Ohio)
- us-west-1 (US West, N. California)
- us-west-2 (US West, Oregon)
- eu-west-1 (EU West, Ireland)
- eu-central-1 (EU Central, Frankfurt)
- ap-northeast-1 (Asia Pacific, Tokyo)
- ap-southeast-1 (Asia Pacific, Singapore)
- ap-southeast-2 (Asia Pacific, Sydney)

You're currently using the us-east-1 region.
```

**Using Prompt Templates**:
```
User: I need to perform a security audit of my S3 buckets

Claude: I'll help you audit the security of your S3 buckets.

Here are AWS CLI commands to perform a comprehensive security audit:

# List all buckets with public access settings
aws s3api list-buckets --query 'Buckets[*].Name' --output text | xargs -I {} aws s3api get-public-access-block --bucket {}

# Check bucket policies for public access
aws s3api list-buckets --query 'Buckets[*].Name' --output text | xargs -I {} aws s3api get-bucket-policy --bucket {} 2>/dev/null

# Identify buckets without encryption
aws s3api list-buckets --query 'Buckets[*].Name' --output text | xargs -I {} aws s3api get-bucket-encryption --bucket {} 2>/dev/null

# Check for buckets without logging enabled
aws s3api list-buckets --query 'Buckets[*].Name' --output text | xargs -I {} aws s3api get-bucket-logging --bucket {} 2>/dev/null

# Verify bucket versioning status
aws s3api list-buckets --query 'Buckets[*].Name' --output text | xargs -I {} aws s3api get-bucket-versioning --bucket {}
```

## Available Prompt Templates

The AWS MCP Server includes the following pre-defined prompt templates:

### Core Operations

| Prompt                 | Description                                                   | Parameters                                          |
|------------------------|---------------------------------------------------------------|-----------------------------------------------------|
| `create_resource`      | Generate commands to create AWS resources with best practices | `resource_type`, `resource_name`                    |
| `resource_inventory`   | Create comprehensive inventory of resources                   | `service`, `region` (optional)                      |
| `troubleshoot_service` | Generate commands to troubleshoot service issues              | `service`, `resource_id`                            |
| `resource_cleanup`     | Identify and safely clean up resources                        | `service`, `criteria` (optional)                    |

### Security & Compliance

| Prompt                     | Description                                                | Parameters                                          |
|----------------------------|------------------------------------------------------------|-----------------------------------------------------|
| `security_audit`           | Audit security settings for a specific AWS service         | `service`                                           |
| `security_posture_assessment` | Comprehensive security assessment across your AWS environment | None                                          |
| `iam_policy_generator`     | Create least-privilege IAM policies                        | `service`, `actions`, `resource_pattern` (optional) |
| `compliance_check`         | Check compliance with standards                            | `compliance_standard`, `service` (optional)         |

### Cost & Performance

| Prompt               | Description                                             | Parameters                                         |
|----------------------|---------------------------------------------------------|----------------------------------------------------|
| `cost_optimization`  | Find cost optimization opportunities for a service      | `service`                                          |
| `performance_tuning` | Optimize and tune performance of AWS resources          | `service`, `resource_id`                           |

### Infrastructure & Architecture

| Prompt                      | Description                                              | Parameters                                           |
|-----------------------------|----------------------------------------------------------|------------------------------------------------------|
| `serverless_deployment`     | Deploy serverless applications with best practices       | `application_name`, `runtime` (optional)             |
| `container_orchestration`   | Set up container environments (ECS/EKS)                  | `cluster_name`, `service_type` (optional)            |
| `vpc_network_design`        | Design and implement secure VPC networking               | `vpc_name`, `cidr_block` (optional)                  |
| `infrastructure_automation` | Automate infrastructure management                       | `resource_type`, `automation_scope` (optional)       |
| `multi_account_governance`  | Implement secure multi-account strategies                | `account_type` (optional)                            |

### Reliability & Monitoring

| Prompt               | Description                                           | Parameters                                          |
|----------------------|-------------------------------------------------------|-----------------------------------------------------|
| `service_monitoring` | Set up comprehensive monitoring                       | `service`, `metric_type` (optional)                 |
| `disaster_recovery`  | Implement enterprise-grade DR solutions               | `service`, `recovery_point_objective` (optional)    |

## Security

The AWS MCP Server implements a comprehensive multi-layered approach to command validation and security:

### Command Validation System

The server validates all AWS CLI commands through a three-layer system:

1. **Basic Command Structure**: 
   - Verifies commands start with 'aws' prefix and contain a valid service
   - Ensures proper command syntax

2. **Security-Focused Command Filtering**:
   - **Dangerous Commands**: Blocks commands that could compromise security
   - **Safe Patterns**: Explicitly allows read-only operations needed for normal use
   - **Regex Pattern Matching**: Prevents complex security risks with pattern matching

3. **Pipe Command Security**:
   - Validates Unix commands used in pipes
   - Restricts commands to a safe allowlist
   - Prevents filesystem manipulation and arbitrary command execution

### Default Security Configuration

The default security configuration focuses on preventing the following attack vectors:

#### 1. Identity and Access Management (IAM) Risks

| Blocked Command | Security Risk |
|-----------------|---------------|
| `aws iam create-user` | Creates potential backdoor accounts with persistent access |
| `aws iam create-access-key` | Creates long-term credentials that can be stolen or misused |
| `aws iam attach-*-policy` | Potential privilege escalation via policy attachments |
| `aws iam put-user-policy` | Inline policies can grant excessive permissions |
| `aws iam create-policy` | Creating new policies with potentially dangerous permissions |
| `aws iam create-login-profile` | Creates console passwords for existing users |
| `aws iam deactivate-mfa-device` | Disables multi-factor authentication, weakening security |
| `aws iam update-assume-role-policy` | Modifies trust relationships, enabling privilege escalation |

#### 2. Audit and Logging Tampering

| Blocked Command | Security Risk |
|-----------------|---------------|
| `aws cloudtrail delete-trail` | Removes audit trail of AWS activity |
| `aws cloudtrail stop-logging` | Stops collecting activity logs, creating blind spots |
| `aws cloudtrail update-trail` | Can redirect or modify logging configuration |
| `aws config delete-configuration-recorder` | Disables AWS Config recording of resource changes |
| `aws guardduty delete-detector` | Disables threat detection capabilities |

#### 3. Sensitive Data Access and Protection

| Blocked Command | Security Risk |
|-----------------|---------------|
| `aws secretsmanager put-secret-value` | Modifies sensitive credentials |
| `aws secretsmanager delete-secret` | Removes sensitive credentials |
| `aws kms schedule-key-deletion` | Schedules deletion of encryption keys, risking data loss |
| `aws kms disable-key` | Disables encryption keys, potentially exposing data |
| `aws s3api put-bucket-policy` | Can create public S3 buckets, exposing data |
| `aws s3api delete-bucket-policy` | Removes protective policies from buckets |

#### 4. Network Security Risks

| Blocked Command | Security Risk |
|-----------------|---------------|
| `aws ec2 authorize-security-group-ingress` | Opens inbound network access, potential exposure |
| `aws ec2 authorize-security-group-egress` | Opens outbound network access, potential data exfiltration |
| `aws ec2 modify-instance-attribute` | Can alter security properties of instances |

Many read-only operations that match these patterns are explicitly allowed via safe patterns:

- All `get-`, `list-`, and `describe-` commands
- All help commands (`--help`, `help`)
- Simulation and testing commands (e.g., `aws iam simulate-custom-policy`)

### Configuration Options

- **Security Modes**:
  - `strict` (default): Enforces all security validations
  - `permissive`: Logs warnings but allows execution (use with caution)

- **Custom Configuration**:
  - Override default security rules via YAML configuration file
  - Configure service-specific dangerous commands
  - Define custom safe patterns and regex rules
  - Environment variable: `AWS_MCP_SECURITY_CONFIG`

- **Execution Controls**:
  - Timeouts prevent long-running commands (default: 300 seconds)
  - Output size limits prevent memory issues
  - Environment variables: `AWS_MCP_TIMEOUT`, `AWS_MCP_MAX_OUTPUT`

### Custom Security Rules Example

You can create custom security rules by defining a YAML configuration file:

```yaml
# Example custom security configuration
# Save to a file and set AWS_MCP_SECURITY_CONFIG environment variable

# Dangerous commands to block
dangerous_commands:
  iam:
    # Only block specific IAM operations for your environment
    - "aws iam create-user"
    - "aws iam attach-user-policy"
  
  # Custom service restrictions for your organization
  lambda:
    - "aws lambda delete-function"
    - "aws lambda remove-permission"
  
  # Prevent accidental DynamoDB table deletion
  dynamodb:
    - "aws dynamodb delete-table"

# Safe patterns to explicitly allow
safe_patterns:
  # Global safe patterns
  general:
    - "--help"
    - "--dry-run"
  
  # Allow read operations on IAM
  iam:
    - "aws iam get-"
    - "aws iam list-"
  
  # Allow specific Lambda operations
  lambda:
    - "aws lambda list-functions"
    - "aws lambda get-function"

# Complex regex rules for security validation
regex_rules:
  general:
    # Prevent use of root credentials
    - pattern: "aws .* --profile\\s+root"
      description: "Prevent use of root profile"
      error_message: "Using the root profile is not allowed for security reasons"
  
  iam:
    # Block creation of admin users
    - pattern: "aws iam create-user.*--user-name\\s+.*admin.*"
      description: "Prevent creation of admin users"
      error_message: "Creating users with 'admin' in the name is restricted"
    
    # Prevent wildcards in IAM policies
    - pattern: "aws iam create-policy.*\"Effect\":\\s*\"Allow\".*\"Action\":\\s*\"\\*\".*\"Resource\":\\s*\"\\*\""
      description: "Prevent wildcards in policies"
      error_message: "Creating policies with '*' wildcards for both Action and Resource is not allowed"
  
  s3:
    # Prevent public bucket policies
    - pattern: "aws s3api put-bucket-policy.*\"Effect\":\\s*\"Allow\".*\"Principal\":\\s*\"\\*\""
      description: "Prevent public bucket policies"
      error_message: "Creating bucket policies with public access is restricted"
```

### Security Examples

The system follows IAM best practices, focusing on preventing escalation of privilege:

```bash
# This command would be blocked (creates user)
aws iam create-user --user-name new-user
> Error: This command (aws iam create-user) is restricted for security reasons.

# This command would be blocked (attaches admin policy)
aws iam attach-user-policy --user-name any-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
> Error: Attaching Administrator policies is restricted for security reasons.

# This command would be blocked (opens SSH port globally)
aws ec2 authorize-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0
> Error: Opening non-web ports to the entire internet (0.0.0.0/0) is restricted.

# These commands are allowed (read-only operations)
aws iam list-users
aws s3 ls
aws ec2 describe-instances
```

### Security Best Practices

- Always use the default `strict` security mode in production
- Follow the deployment recommendations in [Security Considerations](#security-considerations)
- Run with least-privilege AWS credentials
- For custom configurations, focus on your security requirements

## Development

### Setting Up the Development Environment

```bash
# Install only runtime dependencies using pip
pip install -e .

# Install all development dependencies using pip
pip install -e ".[dev]"

# Or use uv for faster dependency management
make uv-install       # Install runtime dependencies
make uv-dev-install   # Install development dependencies
```

### Makefile Commands

The project includes a Makefile with various targets for common tasks:

```bash
# Test commands
make test             # Run tests excluding integration tests
make test-unit        # Run unit tests only (all tests except integration tests)
make test-integration # Run integration tests only (requires AWS credentials)
make test-all         # Run all tests including integration tests

# Test coverage commands
make test-coverage    # Run tests with coverage report (excluding integration tests)
make test-coverage-all # Run all tests with coverage report (including integration tests)

# Linting and formatting
make lint             # Run linters (ruff check and format --check)
make lint-fix         # Run linters and auto-fix issues where possible
make format           # Format code with ruff
```

For a complete list of available commands, run `make help`.

### Code Coverage

The project includes configuration for [Codecov](https://codecov.io) to track code coverage metrics. The configuration is in the `codecov.yml` file, which:

- Sets a target coverage threshold of 80%
- Excludes test files, setup files, and documentation from coverage reports
- Configures PR comments and status checks

Coverage reports are automatically generated during CI/CD runs and uploaded to Codecov.

### Integration Testing

Integration tests verify AWS MCP Server works correctly with actual AWS resources. To run them:

1. **Set up AWS resources**:
   - Create an S3 bucket for testing
   - Set the environment variable: `export AWS_TEST_BUCKET=your-test-bucket-name`
   - Ensure your AWS credentials are configured

2. **Run integration tests**:
   ```bash
   # Run all tests including integration tests
   make test-all
   
   # Run only integration tests
   make test-integration
   ```

Or you can run the pytest commands directly:
```bash
# Run all tests including integration tests
pytest --run-integration

# Run only integration tests
pytest --run-integration -m integration
```

## Troubleshooting

- **Authentication Issues**: Ensure your AWS credentials are properly configured
- **Connection Errors**: Verify the server is running and AI assistant connection settings are correct
- **Permission Errors**: Check that your AWS credentials have the necessary permissions
- **Timeout Errors**: For long-running commands, increase the `AWS_MCP_TIMEOUT` environment variable

## Why Deploy with Docker

Deploying AWS MCP Server via Docker is the recommended approach, offering significant security and reliability advantages that form the core of the tool's secure usage pattern:

### Security Benefits

- **Isolation (Primary Mitigation):** The Docker container provides essential filesystem and process isolation. AWS CLI commands and piped Unix utilities run in a contained environment. Accidental or misused commands affecting the filesystem are limited to the container, **protecting your host machine**.
- **Controlled Credential Access:** When mounting credentials, using the `:ro` (read-only) flag limits the container's ability to modify your AWS configuration files.
- **No Local Installation:** Avoids installing the AWS CLI and its dependencies directly on your host system.
- **Clean Environment:** Each container run starts with a known, clean state.

### Reliability Advantages

- **Consistent Configuration**: All required tools (AWS CLI, SSM plugin, jq) are pre-installed and properly configured
- **Dependency Management**: Avoid version conflicts between tools and dependencies
- **Cross-Platform Consistency**: Works the same way across different operating systems
- **Complete Environment**: Includes all necessary tools for command pipes, filtering, and formatting

### Other Benefits

- **Multi-Architecture Support**: Runs on both Intel/AMD (x86_64) and ARM (Apple Silicon, AWS Graviton) processors
- **Simple Updates**: Update to new versions with a single pull command
- **No Python Environment Conflicts**: Avoids potential conflicts with other Python applications on your system
- **Version Pinning**: Easily pin to specific versions for stability in production environments

## Versioning

This project uses [setuptools_scm](https://github.com/pypa/setuptools_scm) to automatically determine versions based on Git tags:

- **Release versions**: When a Git tag exists (e.g., `1.2.3`), the version will be exactly that tag
- **Development versions**: For commits without tags, a development version is generated in the format: 
  `<last-tag>.post<commits-since-tag>+g<commit-hash>.d<date>` (e.g., `1.2.3.post10+gb697684.d20250406`)

The version is automatically included in:
- Package version information
- Docker image labels
- Continuous integration builds

### Creating Releases

To create a new release version:

```bash
# Create and push a new tag
git tag -a 1.2.3 -m "Release version 1.2.3"
git push origin 1.2.3
```

The CI/CD pipeline will automatically build and publish Docker images with appropriate version tags.

For more detailed information about the version management system, see [VERSION.md](docs/VERSION.md).

## License

This project is licensed under the MIT License - see the LICENSE file for details.
