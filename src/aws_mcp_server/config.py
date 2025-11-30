"""Configuration settings for the AWS MCP Server.

This module contains configuration settings for the AWS MCP Server.

Environment variables:
- AWS_MCP_TIMEOUT: Custom timeout in seconds (default: 300)
- AWS_MCP_MAX_OUTPUT: Maximum output size in characters (default: 100000)
- AWS_MCP_TRANSPORT: Transport protocol to use ("stdio" or "sse", default: "stdio")
- AWS_PROFILE: AWS profile to use (default: "default")
- AWS_REGION: AWS region to use (default: "us-east-1")
- AWS_DEFAULT_REGION: Alternative to AWS_REGION (used if AWS_REGION not set)
- AWS_MCP_SANDBOX: Sandbox mode ("auto", "disabled", "required", default: "auto")
- AWS_MCP_SANDBOX_CREDENTIALS: How to pass AWS credentials to sandbox
  ("env", "aws_config", "both", default: "both")
"""

import os
from pathlib import Path

DEFAULT_TIMEOUT = int(os.environ.get("AWS_MCP_TIMEOUT", "300"))
MAX_OUTPUT_SIZE = int(os.environ.get("AWS_MCP_MAX_OUTPUT", "100000"))
TRANSPORT = os.environ.get("AWS_MCP_TRANSPORT", "stdio")
AWS_PROFILE = os.environ.get("AWS_PROFILE", "default")
AWS_REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))

# Sandbox mode: "auto" (use if available), "disabled" (never use), "required" (fail if unavailable)
SANDBOX_MODE = os.environ.get("AWS_MCP_SANDBOX", "auto").lower()
# Credential mode: "env" (environment only), "aws_config" (~/.aws only), "both" (default)
SANDBOX_CREDENTIAL_MODE = os.environ.get("AWS_MCP_SANDBOX_CREDENTIALS", "both").lower()

INSTRUCTIONS = """
AWS MCP Server provides access to the entire AWS CLI through two tools.

RECOMMENDED WORKFLOW:
1. Use aws_cli_help to learn command syntax before executing
2. Use aws_cli_pipeline to execute commands, optionally with Unix pipes

TOOLS:
- aws_cli_help: Get documentation for any AWS service or command
  Example: aws_cli_help(service="s3", command="cp") -> shows s3 cp usage

- aws_cli_pipeline: Execute AWS CLI commands with optional Unix pipes
  Example: aws s3 ls
  Example: aws ec2 describe-instances | jq '.Reservations[].Instances[].InstanceId'

AWS RESOURCES (read these for context):
  - aws://config/profiles: List available AWS profiles and active profile
  - aws://config/regions: List available AWS regions and active region
  - aws://config/regions/{region}: Get detailed information about a specific region 
    including name, code, availability zones, geographic location, and available services
  - aws://config/environment: Get current AWS environment details (profile, region, credentials)
  - aws://config/account: Get current AWS account information (ID, alias, organization)
- Use the built-in prompt templates for common AWS tasks following AWS Well-Architected Framework best practices:

  Essential Operations:
  - create_resource: Create AWS resources with comprehensive security settings
  - resource_inventory: Create detailed resource inventories across regions
  - troubleshoot_service: Perform systematic service issue diagnostics

  Security & Compliance:
  - security_audit: Perform comprehensive service security audits
  - security_posture_assessment: Evaluate overall AWS security posture
  - iam_policy_generator: Generate least-privilege IAM policies
  - compliance_check: Verify compliance with regulatory standards

  Cost & Performance:
  - cost_optimization: Find and implement cost optimization opportunities
  - resource_cleanup: Safely clean up unused resources
  - performance_tuning: Optimize performance for specific resources

  Infrastructure & Architecture:
  - serverless_deployment: Deploy serverless applications with best practices
  - container_orchestration: Set up container environments (ECS/EKS)
  - vpc_network_design: Design and deploy secure VPC networking
  - infrastructure_automation: Automate infrastructure management
  - multi_account_governance: Implement secure multi-account strategies

  Reliability & Monitoring:
  - service_monitoring: Configure comprehensive service monitoring
  - disaster_recovery: Implement enterprise-grade DR solutions
"""

BASE_DIR = Path(__file__).parent.parent.parent
