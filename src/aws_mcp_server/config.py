"""Configuration settings for the AWS MCP Server.

This module contains configuration settings for the AWS MCP Server.

Environment variables:
- AWS_MCP_TIMEOUT: Custom timeout in seconds (default: 300)
- AWS_MCP_MAX_OUTPUT: Maximum output size in characters (default: 100000)
- AWS_MCP_TRANSPORT: Transport protocol to use ("stdio" or "sse", default: "stdio")
- AWS_PROFILE: AWS profile to use (default: "default")
- AWS_REGION: AWS region to use (default: "us-east-1")
- AWS_DEFAULT_REGION: Alternative to AWS_REGION (used if AWS_REGION not set)
- AWS_MCP_SECURITY_MODE: Security mode for command validation (strict or permissive, default: strict)
- AWS_MCP_SECURITY_CONFIG: Path to custom security configuration file
- AWS_MCP_SANDBOX: Sandbox mode ("auto", "disabled", "required", default: "auto")
- AWS_MCP_SANDBOX_CREDENTIALS: How to pass AWS credentials to sandbox
  ("env", "aws_config", "both", default: "both")
"""

import os
from pathlib import Path

# Command execution settings
DEFAULT_TIMEOUT = int(os.environ.get("AWS_MCP_TIMEOUT", "300"))
MAX_OUTPUT_SIZE = int(os.environ.get("AWS_MCP_MAX_OUTPUT", "100000"))

# Transport protocol
TRANSPORT = os.environ.get("AWS_MCP_TRANSPORT", "stdio")

# AWS CLI settings
AWS_PROFILE = os.environ.get("AWS_PROFILE", "default")
AWS_REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))

# Security settings
SECURITY_MODE = os.environ.get("AWS_MCP_SECURITY_MODE", "strict")
SECURITY_CONFIG_PATH = os.environ.get("AWS_MCP_SECURITY_CONFIG", "")

# Sandbox settings
# "auto" - use sandbox if available, fall back to no sandbox
# "disabled" - never use sandbox
# "required" - fail if sandbox is not available
SANDBOX_MODE = os.environ.get("AWS_MCP_SANDBOX", "auto").lower()
# "env" - pass AWS credentials via environment variables only
# "aws_config" - allow read access to ~/.aws directory only
# "both" - both environment variables and ~/.aws access (default)
SANDBOX_CREDENTIAL_MODE = os.environ.get("AWS_MCP_SANDBOX_CREDENTIALS", "both").lower()

# Instructions displayed to client during initialization
INSTRUCTIONS = """
AWS MCP Server provides a comprehensive interface to the AWS CLI with best practices guidance.
- Use the describe_command tool to get AWS CLI documentation
- Use the execute_command tool to run AWS CLI commands
- The execute_command tool supports Unix pipes (|) to filter or transform AWS CLI output:
  Example: aws s3api list-buckets --query 'Buckets[*].Name' --output text | sort
- Access AWS environment resources for context:
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

# Application paths
BASE_DIR = Path(__file__).parent.parent.parent
