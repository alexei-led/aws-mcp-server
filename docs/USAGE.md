# User Guide

This guide details how to use the AWS MCP Server with AI assistants like Claude Desktop or Cursor. It covers tools, resources, and prompt templates designed to make AWS interactions safe and efficient.

## Table of Contents

- [Getting Started](#getting-started)
- [Claude Desktop Integration](#claude-desktop-integration)
- [Core Tools](#core-tools)
- [Context Resources](#context-resources)
- [Prompt Templates](#prompt-templates)
- [Best Practices](#best-practices)

## Getting Started

You can run the AWS MCP Server using Docker (recommended), uvx, or pip.

### Docker (Recommended)

```bash
docker run -i --rm \
  -v ~/.aws:/home/appuser/.aws:ro \
  ghcr.io/alexei-led/aws-mcp-server:latest
```

### uvx (Quick)

```bash
# Requires Python 3.13+ and AWS CLI installed
uvx alexei-led.aws-mcp-server
```

### pip

```bash
# Requires Python 3.13+ and AWS CLI installed
pip install alexei-led.aws-mcp-server
aws-mcp-server
```

See the [README](../README.md) for full installation and configuration details.

## Claude Desktop Integration

To use this server with Claude Desktop, add it to your configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Using uvx (Recommended)

```json
{
  "mcpServers": {
    "aws": {
      "command": "uvx",
      "args": ["alexei-led.aws-mcp-server"]
    }
  }
}
```

### Using Docker

```json
{
  "mcpServers": {
    "aws": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "/Users/YOUR_USERNAME/.aws:/home/appuser/.aws:ro",
        "ghcr.io/alexei-led/aws-mcp-server:latest"
      ]
    }
  }
}
```

> **Note**: Update `/Users/YOUR_USERNAME/.aws` to match your local AWS credentials path.

## Core Tools

The server provides two primary tools that give you access to the full AWS CLI.

### `aws_cli_help`

**Purpose**: Get documentation for any AWS service or command.  
**Usage**: `aws_cli_help(command="s3 cp")`

Use this tool to learn command syntax, available options, and examples before executing commands.

### `aws_cli_pipeline`

**Purpose**: Execute AWS CLI commands securely.  
**Usage**: `aws_cli_pipeline(command="aws s3 ls")`

This tool runs the command and returns the output. It supports Unix pipes for filtering.

**Examples:**

1. **List S3 Buckets**:
   `aws s3 ls`

2. **Filter Output with `jq`**:
   `aws ec2 describe-instances | jq '.Reservations[].Instances[].InstanceId'`

3. **Find a Specific Log Group**:
   `aws logs describe-log-groups | grep "production"`

## Context Resources

Resources allow the AI to read configuration and state from your environment.

| Resource Name       | URI                             | Description                                                    |
| :------------------ | :------------------------------ | :------------------------------------------------------------- |
| **AWS Profiles**    | `aws://config/profiles`         | Lists available AWS profiles in your config/credentials files. |
| **AWS Regions**     | `aws://config/regions`          | Lists all available AWS regions with descriptions.             |
| **Region Details**  | `aws://config/regions/{region}` | Detailed info for a region (AZs, available services).          |
| **AWS Environment** | `aws://config/environment`      | Current active profile, region, and credential status.         |
| **AWS Account**     | `aws://config/account`          | Current Account ID and Account Alias.                          |

**Example Usage**:

> "Check `aws://config/environment` to see which region I am currently connected to."

## Prompt Templates

Pre-defined prompts help you generate complex commands following AWS best practices.

### Core Operations

- **`create_resource`**: Generate creation commands with security best practices.
  - _Params_: `resource_type` (e.g., "s3-bucket"), `resource_name`
- **`resource_inventory`**: List resources with key details and metadata.
  - _Params_: `service` (e.g., "ec2"), `region` (default: "all")
- **`resource_cleanup`**: Find unused resources for potential deletion.
  - _Params_: `service`, `criteria` (default: "unused")
- **`troubleshoot_service`**: Diagnose issues with a specific resource.
  - _Params_: `service`, `resource_id`

### Security & Compliance

- **`security_audit`**: Audit a specific service for security risks.
  - _Params_: `service`
- **`security_posture_assessment`**: Account-wide security check (Security Hub, GuardDuty, etc.).
- **`iam_policy_generator`**: Create least-privilege IAM policies.
  - _Params_: `service`, `actions`, `resource_pattern`
- **`compliance_check`**: Check compliance with standards (HIPAA, PCI, etc.).
  - _Params_: `compliance_standard`, `service`

### Cost & Performance

- **`cost_optimization`**: Find cost savings (idle resources, sizing).
  - _Params_: `service`
- **`performance_tuning`**: Analyze metrics and suggest tuning.
  - _Params_: `service`, `resource_id`

### Infrastructure & Architecture

- **`serverless_deployment`**: Deploy Lambda/API Gateway apps.
  - _Params_: `application_name`, `runtime` (default: "python3.12")
- **`container_orchestration`**: Setup ECS/EKS clusters.
  - _Params_: `cluster_name`, `service_type` (default: "fargate")
- **`vpc_network_design`**: Design a secure VPC with subnets.
  - _Params_: `vpc_name`, `cidr_block`
- **`infrastructure_automation`**: Setup SSM automation or EventBridge rules.
  - _Params_: `resource_type`, `automation_scope`
- **`multi_account_governance`**: Setup AWS Organizations/Control Tower structures.
  - _Params_: `account_type`

### Reliability & Monitoring

- **`service_monitoring`**: Setup CloudWatch alarms and dashboards.
  - _Params_: `service`, `metric_type`
- **`disaster_recovery`**: Setup backups and DR plans.
  - _Params_: `service`, `recovery_point_objective`

## Best Practices

1. **Check Help First**: Always ask the AI to check `aws_cli_help` if it's unsure about a command's syntax.
2. **Dry Runs**: For destructive operations, ask the AI to generate a command with `--dry-run` (if supported) or review the command before execution.
3. **Least Privilege**: Ensure the AWS credentials you provide to the server have only the permissions necessary for your current task.
4. **Use Resources**: Ask the AI to read `aws://config/account` or `aws://config/environment` to verify context before running commands.
