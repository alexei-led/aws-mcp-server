# Usage Guide

This guide covers the tools, resources, and prompt templates provided by the AWS MCP Server.

For installation and setup, see the [README](../README.md).

## Table of Contents

- [Core Tools](#core-tools)
- [Context Resources](#context-resources)
- [Prompt Templates](#prompt-templates)
- [Best Practices](#best-practices)

## Core Tools

The server provides two tools that give Claude access to the full AWS CLI.

### `aws_cli_help`

**Purpose**: Get documentation for any AWS service or command.

**Parameters**:

- `service` (required): AWS service name (e.g., "s3", "ec2", "lambda")
- `command` (optional): Specific command within the service (e.g., "ls", "describe-instances")

**Examples**:

```
aws_cli_help(service="s3")              # General S3 help
aws_cli_help(service="s3", command="cp") # Help for s3 cp command
aws_cli_help(service="ec2", command="describe-instances")
```

Use this tool first to learn command syntax before executing.

### `aws_cli_pipeline`

**Purpose**: Execute AWS CLI commands with optional Unix pipes.

**Parameters**:

- `command` (required): The AWS CLI command (must start with `aws`)
- `timeout` (optional): Command timeout in seconds (default: 300)

**Examples**:

```bash
# Simple command
aws s3 ls

# With output filtering
aws ec2 describe-instances | jq '.Reservations[].Instances[].InstanceId'

# Chain multiple filters
aws logs describe-log-groups | grep "production" | head -10

# Complex queries
aws ec2 describe-instances --query 'Reservations[].Instances[?State.Name==`running`].[InstanceId,Tags[?Key==`Name`].Value]' --output table
```

## Context Resources

Resources provide Claude with read-only access to your AWS configuration and environment.

| Resource           | URI                             | Description                                 |
| ------------------ | ------------------------------- | ------------------------------------------- |
| **Profiles**       | `aws://config/profiles`         | Available AWS profiles from `~/.aws/config` |
| **Regions**        | `aws://config/regions`          | All AWS regions with descriptions           |
| **Region Details** | `aws://config/regions/{region}` | AZs and services for a specific region      |
| **Environment**    | `aws://config/environment`      | Current profile, region, credential status  |
| **Account**        | `aws://config/account`          | Account ID and alias                        |

**Example Usage**:

Ask Claude: _"Check `aws://config/environment` to see which region I'm connected to"_

## Prompt Templates

Pre-defined prompts help generate AWS commands following best practices.

### Core Operations

| Prompt                 | Purpose                                                 | Parameters                              |
| ---------------------- | ------------------------------------------------------- | --------------------------------------- |
| `create_resource`      | Generate creation commands with security best practices | `resource_type`, `resource_name`        |
| `resource_inventory`   | List resources with metadata                            | `service`, `region` (default: all)      |
| `resource_cleanup`     | Find unused resources                                   | `service`, `criteria` (default: unused) |
| `troubleshoot_service` | Diagnose resource issues                                | `service`, `resource_id`                |

### Security & Compliance

| Prompt                        | Purpose                          | Parameters                               |
| ----------------------------- | -------------------------------- | ---------------------------------------- |
| `security_audit`              | Audit service for security risks | `service`                                |
| `security_posture_assessment` | Account-wide security check      | —                                        |
| `iam_policy_generator`        | Create least-privilege policies  | `service`, `actions`, `resource_pattern` |
| `compliance_check`            | Check compliance standards       | `compliance_standard`, `service`         |

### Cost & Performance

| Prompt               | Purpose                    | Parameters               |
| -------------------- | -------------------------- | ------------------------ |
| `cost_optimization`  | Find cost savings          | `service`                |
| `performance_tuning` | Analyze and suggest tuning | `service`, `resource_id` |

### Infrastructure

| Prompt                    | Purpose                   | Parameters                            |
| ------------------------- | ------------------------- | ------------------------------------- |
| `serverless_deployment`   | Deploy Lambda/API Gateway | `application_name`, `runtime`         |
| `container_orchestration` | Setup ECS/EKS             | `cluster_name`, `service_type`        |
| `vpc_network_design`      | Design secure VPC         | `vpc_name`, `cidr_block`              |
| `service_monitoring`      | Setup CloudWatch alarms   | `service`, `metric_type`              |
| `disaster_recovery`       | Setup backups and DR      | `service`, `recovery_point_objective` |

## Best Practices

1. **Check Help First**: Ask Claude to use `aws_cli_help` before running unfamiliar commands
2. **Verify Context**: Use `aws://config/environment` to confirm profile and region
3. **Dry Runs**: For destructive operations, ask Claude to use `--dry-run` when supported
4. **Least Privilege**: Ensure your AWS credentials have only necessary permissions
5. **Review Commands**: Ask Claude to show the command before executing sensitive operations
