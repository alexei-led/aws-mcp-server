"""AWS CLI prompt definitions for the AWS MCP Server.

This module provides concise, example-driven prompt templates for common AWS use cases.
Each prompt leads with a concrete CLI example and specifies the expected output format.
"""

import logging

logger = logging.getLogger(__name__)

# Service-specific CLI examples for common operations
_SECURITY_EXAMPLES = {
    "s3": "aws s3api get-public-access-block --bucket BUCKET",
    "ec2": ("aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'"),
    "iam": ("aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d"),
    "rds": "aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`]'",
}

_COST_EXAMPLES = {
    "ec2": ("aws ce get-cost-and-usage --time-period Start=$(date -v-30d +%Y-%m-%d),End=$(date +%Y-%m-%d) --granularity DAILY --metrics UnblendedCost"),
    "s3": ("aws s3api list-buckets --query 'Buckets[].Name' | xargs -I {} aws s3api get-bucket-location --bucket {}"),
    "rds": ("aws rds describe-db-instances --query 'DBInstances[?DBInstanceStatus==`stopped`].[DBInstanceIdentifier,DBInstanceClass]'"),
}

_INVENTORY_EXAMPLES = {
    "ec2": ("aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,Tags[?Key==`Name`].Value|[0]]' --output table"),
    "s3": "aws s3api list-buckets --query 'Buckets[].[Name,CreationDate]' --output table",
    "rds": ("aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceClass,Engine,DBInstanceStatus]' --output table"),
    "lambda": ("aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,MemorySize,LastModified]' --output table"),
}


def register_prompts(mcp):
    """Register all prompts with the MCP server instance.

    Args:
        mcp: The FastMCP server instance
    """
    logger.info("Registering AWS prompt templates")

    @mcp.prompt(
        name="create_resource",
        description="Generate AWS CLI commands to create a resource with security best practices",
    )
    def create_resource(resource_type: str, resource_name: str) -> str:
        """Generate commands to create an AWS resource."""
        examples = {
            "s3-bucket": (
                f"aws s3api create-bucket --bucket {resource_name} --region us-east-1\n"
                f"aws s3api put-public-access-block --bucket {resource_name} \\\n"
                "  --public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,"
                "BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ),
            "ec2-instance": (
                f"aws ec2 run-instances --image-id ami-xxx --instance-type t3.micro \\\n"
                f"  --key-name mykey \\\n"
                f"  --tag-specifications "
                f"'ResourceType=instance,Tags=[{{Key=Name,Value={resource_name}}}]'"
            ),
            "lambda": (
                f"aws lambda create-function --function-name {resource_name} \\\n"
                "  --runtime python3.12 --handler index.handler \\\n"
                "  --role arn:aws:iam::ACCOUNT:role/lambda-role \\\n"
                "  --zip-file fileb://code.zip"
            ),
        }
        example = examples.get(resource_type, f"aws {resource_type} create-* --name {resource_name}")

        return f"""Create {resource_type} named "{resource_name}" with encryption and least-privilege access.

Example:
{example}

Include: creation command, encryption config, resource tags (Name, Environment, Owner), IAM role if needed, verification command.
Output as numbered steps with the CLI command and brief explanation."""

    @mcp.prompt(
        name="security_audit",
        description="Generate AWS CLI commands to audit security for a service",
    )
    def security_audit(service: str) -> str:
        """Generate security audit commands for a service."""
        example = _SECURITY_EXAMPLES.get(
            service,
            f"aws {service} describe-* --query '*[?PubliclyAccessible==`true`]'",
        )

        return f"""Security audit for {service}. Find: public access, weak encryption, overly permissive IAM, unused credentials.

Example:
{example}

Check: public exposure, encryption at rest/transit, security groups, IAM policies, logging enabled.
Output: numbered commands, each with what security issue it detects. Group by severity (High/Medium/Low)."""

    @mcp.prompt(
        name="cost_optimization",
        description="Generate AWS CLI commands to find cost savings for a service",
    )
    def cost_optimization(service: str) -> str:
        """Generate cost optimization commands."""
        example = _COST_EXAMPLES.get(
            service,
            (
                "aws ce get-cost-and-usage --time-period Start=2024-01-01,End=2024-01-31 "
                "--granularity MONTHLY --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE"
            ),
        )

        return f"""Find cost optimization opportunities for {service}.

Example:
{example}

Find: unused/idle resources, oversized instances, missing reserved capacity, untagged resources.
Output: numbered commands with estimated monthly savings for each finding."""

    @mcp.prompt(
        name="resource_inventory",
        description="Generate AWS CLI commands to list all resources for a service",
    )
    def resource_inventory(service: str, region: str = "all") -> str:
        """Generate resource inventory commands."""
        example = _INVENTORY_EXAMPLES.get(service, f"aws {service} describe-* --output table")
        region_flag = "" if region == "all" else f" --region {region}"
        region_note = (
            "Use --region for each region or iterate with:\nfor r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do ... done"
            if region == "all"
            else ""
        )

        return f"""List all {service} resources{region_flag}.

Example:
{example}

Include: resource ID, type/size, status, key tags, creation date.
{region_note}
Output as table format. Add jq/--query filters for clean output."""

    @mcp.prompt(
        name="troubleshoot_service",
        description="Generate AWS CLI commands to diagnose issues with a resource",
    )
    def troubleshoot_service(service: str, resource_id: str) -> str:
        """Generate troubleshooting commands."""
        examples = {
            "ec2": (f"aws ec2 describe-instance-status --instance-ids {resource_id}\naws ec2 get-console-output --instance-id {resource_id}"),
            "rds": (
                f"aws rds describe-db-instances --db-instance-identifier {resource_id}\n"
                f"aws rds describe-events --source-identifier {resource_id} "
                "--source-type db-instance"
            ),
            "lambda": (
                f"aws lambda get-function --function-name {resource_id}\naws logs filter-log-events --log-group-name /aws/lambda/{resource_id} --limit 50"
            ),
        }
        example = examples.get(service, f"aws {service} describe-* --{service}-id {resource_id}")

        return f"""Troubleshoot {service} resource {resource_id}.

Example:
{example}

Check: status/health, recent events, CloudWatch metrics/logs, network connectivity, IAM permissions, dependent services.
Output: diagnostic commands in order of likelihood to find the issue."""

    @mcp.prompt(
        name="iam_policy_generator",
        description="Generate a least-privilege IAM policy for specific actions",
    )
    def iam_policy_generator(service: str, actions: str, resource_pattern: str = "*") -> str:
        """Generate least-privilege IAM policy."""
        first_action = actions.split(",")[0] if "," in actions else actions
        return f"""Create least-privilege IAM policy for {service} actions: {actions}
Resource: {resource_pattern}

Example policy structure:
{{
  "Version": "2012-10-17",
  "Statement": [{{
    "Effect": "Allow",
    "Action": ["{service}:{first_action}"],
    "Resource": "{resource_pattern}",
    "Condition": {{}}
  }}]
}}

Include: only required actions, resource-level restrictions, useful conditions (aws:SourceVpc, aws:RequestedRegion).
Provide: the policy JSON and `aws iam put-role-policy` command to apply it."""

    @mcp.prompt(
        name="service_monitoring",
        description="Generate AWS CLI commands to set up CloudWatch monitoring",
    )
    def service_monitoring(service: str, metric_type: str = "performance") -> str:
        """Generate monitoring setup commands."""
        examples = {
            "ec2": (
                "aws cloudwatch put-metric-alarm --alarm-name high-cpu \\\n"
                "  --metric-name CPUUtilization --namespace AWS/EC2 \\\n"
                "  --statistic Average --period 300 --threshold 80 \\\n"
                "  --comparison-operator GreaterThanThreshold --evaluation-periods 2 \\\n"
                "  --alarm-actions arn:aws:sns:REGION:ACCOUNT:alerts"
            ),
            "rds": (
                "aws cloudwatch put-metric-alarm --alarm-name rds-connections \\\n"
                "  --metric-name DatabaseConnections --namespace AWS/RDS \\\n"
                "  --statistic Average --period 300 --threshold 100 \\\n"
                "  --comparison-operator GreaterThanThreshold --evaluation-periods 2"
            ),
            "lambda": (
                "aws cloudwatch put-metric-alarm --alarm-name lambda-errors \\\n"
                "  --metric-name Errors --namespace AWS/Lambda \\\n"
                "  --statistic Sum --period 300 --threshold 5 \\\n"
                "  --comparison-operator GreaterThanThreshold --evaluation-periods 1"
            ),
        }
        example = examples.get(
            service,
            f"aws cloudwatch put-metric-alarm --alarm-name my-alarm \\\n  --metric-name ... --namespace AWS/{service}",
        )

        return f"""Set up {metric_type} monitoring for {service}.

Example:
{example}

Create: CloudWatch alarms for key metrics, SNS topic for notifications, dashboard.
Key {service} metrics to monitor: CPU, memory, connections, errors, latency.
Output: commands to create alarms with sensible thresholds."""

    @mcp.prompt(
        name="disaster_recovery",
        description="Generate AWS CLI commands to set up backups and DR",
    )
    def disaster_recovery(service: str, recovery_point_objective: str = "1 hour") -> str:
        """Generate disaster recovery setup commands."""
        examples = {
            "ec2": (
                "aws ec2 create-snapshot --volume-id vol-xxx --description 'DR backup'\naws backup create-backup-plan --backup-plan file://backup-plan.json"
            ),
            "rds": (
                "aws rds modify-db-instance --db-instance-identifier mydb \\\n"
                "  --backup-retention-period 7 --preferred-backup-window 03:00-04:00\n"
                "aws rds create-db-snapshot --db-instance-identifier mydb \\\n"
                "  --db-snapshot-identifier mydb-manual"
            ),
            "dynamodb": (
                "aws dynamodb update-continuous-backups --table-name mytable \\\n  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"
            ),
        }
        example = examples.get(
            service,
            "aws backup create-backup-plan --backup-plan file://backup-plan.json",
        )

        return f"""Set up disaster recovery for {service} with RPO of {recovery_point_objective}.

Example:
{example}

Configure: automated backups, cross-region replication if RPO < 1 hour, point-in-time recovery.
Include: backup schedule, retention policy, restore procedure test command."""

    @mcp.prompt(
        name="compliance_check",
        description="Generate AWS CLI commands to check compliance with a standard",
    )
    def compliance_check(compliance_standard: str, service: str = "all") -> str:
        """Generate compliance checking commands."""
        scope = f"for {service}" if service != "all" else "account-wide"

        return f"""Check {compliance_standard} compliance {scope}.

Example:
aws securityhub get-findings --filters file://compliance-filter.json
aws configservice get-compliance-details-by-config-rule \\
  --config-rule-name s3-bucket-server-side-encryption-enabled

Key {compliance_standard} checks: encryption, access logging, network isolation, IAM controls.
Output: commands to identify non-compliant resources, grouped by control category."""

    @mcp.prompt(
        name="resource_cleanup",
        description="Generate AWS CLI commands to find and clean up unused resources",
    )
    def resource_cleanup(service: str, criteria: str = "unused") -> str:
        """Generate resource cleanup commands."""
        examples = {
            "ec2": ("aws ec2 describe-volumes --filters Name=status,Values=available \\\n  --query 'Volumes[].[VolumeId,Size,CreateTime]'"),
            "ebs": ("aws ec2 describe-snapshots --owner-ids self \\\n  --query 'Snapshots[?StartTime<`2024-01-01`].[SnapshotId,VolumeSize,StartTime]'"),
            "ami": ("aws ec2 describe-images --owners self \\\n  --query 'Images[?CreationDate<`2024-01-01`].[ImageId,Name,CreationDate]'"),
            "elb": ("aws elbv2 describe-load-balancers \\\n  --query 'LoadBalancers[].[LoadBalancerName,State.Code]' | grep -v active"),
        }
        example = examples.get(service, f"aws {service} describe-* --query '*[?Status==`unused`]'")

        return f"""Find {criteria} {service} resources for cleanup.

Example:
{example}

Find: {criteria} resources, estimate cost savings, create backup before deletion.
Output:
1. List command (dry-run to identify)
2. Backup/snapshot command
3. Delete command with --dry-run first
Include cost estimate for cleanup savings."""

    @mcp.prompt(
        name="serverless_deployment",
        description="Generate AWS CLI commands to deploy a Lambda function",
    )
    def serverless_deployment(application_name: str, runtime: str = "python3.12") -> str:
        """Generate serverless deployment commands."""
        return f"""Deploy serverless application "{application_name}" with {runtime}.

Example:
aws lambda create-function --function-name {application_name} \\
  --runtime {runtime} --handler app.handler \\
  --role arn:aws:iam::ACCOUNT:role/{application_name}-role \\
  --zip-file fileb://deployment.zip \\
  --environment Variables={{ENV=prod}}

aws apigateway create-rest-api --name {application_name}-api

Include: Lambda function, API Gateway (if HTTP), DynamoDB table (if stateful), IAM role with least privilege.
Output: commands in deployment order with verification steps."""

    @mcp.prompt(
        name="container_orchestration",
        description="Generate AWS CLI commands to set up ECS/EKS cluster",
    )
    def container_orchestration(cluster_name: str, service_type: str = "fargate") -> str:
        """Generate container orchestration commands."""
        if service_type == "eks":
            example = f"eksctl create cluster --name {cluster_name} --region us-east-1 \\\n  --nodegroup-name standard --node-type t3.medium --nodes 3"
        else:
            example = (
                f"aws ecs create-cluster --cluster-name {cluster_name} \\\n"
                "  --capacity-providers FARGATE\n"
                f"aws ecs register-task-definition --family {cluster_name}-task \\\n"
                "  --network-mode awsvpc --requires-compatibilities FARGATE \\\n"
                "  --cpu 256 --memory 512 \\\n"
                "  --container-definitions file://container-def.json"
            )

        return f"""Set up {service_type} cluster "{cluster_name}".

Example:
{example}

Include: cluster, task definition, service with desired count, load balancer, IAM roles.
Output: commands in order with verification after each step."""

    @mcp.prompt(
        name="vpc_network_design",
        description="Generate AWS CLI commands to create a VPC with subnets",
    )
    def vpc_network_design(vpc_name: str, cidr_block: str = "10.0.0.0/16") -> str:
        """Generate VPC creation commands."""
        return f"""Create VPC "{vpc_name}" with CIDR {cidr_block}.

Example:
aws ec2 create-vpc --cidr-block {cidr_block} \\
  --tag-specifications 'ResourceType=vpc,Tags=[{{Key=Name,Value={vpc_name}}}]'
aws ec2 create-subnet --vpc-id VPC_ID --cidr-block 10.0.1.0/24 \\
  --availability-zone us-east-1a \\
  --tag-specifications 'ResourceType=subnet,Tags=[{{Key=Name,Value={vpc_name}-public-1a}}]'

Create: VPC, 2+ public subnets, 2+ private subnets, IGW, NAT gateway, route tables.
Output: commands in dependency order (VPC first, then subnets, then gateways)."""

    @mcp.prompt(
        name="infrastructure_automation",
        description="Generate AWS CLI commands for SSM automation",
    )
    def infrastructure_automation(resource_type: str, automation_scope: str = "deployment") -> str:
        """Generate infrastructure automation commands."""
        examples = {
            "patching": ("aws ssm create-maintenance-window --name weekly-patching \\\n  --schedule 'cron(0 2 ? * SUN *)' --duration 3 --cutoff 1"),
            "deployment": (
                "aws ssm create-association --name AWS-RunShellScript \\\n"
                "  --targets Key=tag:Environment,Values=prod \\\n"
                "  --parameters commands=['./deploy.sh']"
            ),
            "scaling": (
                "aws application-autoscaling register-scalable-target \\\n"
                "  --service-namespace ecs \\\n"
                "  --resource-id service/cluster/service \\\n"
                "  --scalable-dimension ecs:service:DesiredCount \\\n"
                "  --min-capacity 1 --max-capacity 10"
            ),
        }
        example = examples.get(
            automation_scope,
            "aws ssm create-document --name my-automation --content file://automation.json",
        )

        return f"""Set up {automation_scope} automation for {resource_type}.

Example:
{example}

Include: SSM document or EventBridge rule, IAM role, notification on completion/failure.
Output: automation definition and schedule/trigger configuration."""

    @mcp.prompt(
        name="security_posture_assessment",
        description="Generate AWS CLI commands for account-wide security assessment",
    )
    def security_posture_assessment() -> str:
        """Generate security posture assessment commands."""
        return """Account-wide security posture assessment.

Example:
aws securityhub get-findings --filters file://critical-findings.json
aws iam generate-credential-report && sleep 5 && \\
  aws iam get-credential-report --output text --query Content | base64 -d
aws guardduty list-findings --detector-id DETECTOR_ID \\
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'

Check: Security Hub findings, IAM credential report, GuardDuty threats, public S3/RDS, root account usage.
Output: commands grouped by category (IAM, Network, Data, Logging), prioritized by severity."""

    @mcp.prompt(
        name="performance_tuning",
        description="Generate AWS CLI commands to analyze and tune resource performance",
    )
    def performance_tuning(service: str, resource_id: str) -> str:
        """Generate performance tuning commands."""
        examples = {
            "ec2": (
                f"aws cloudwatch get-metric-statistics --namespace AWS/EC2 \\\n"
                f"  --metric-name CPUUtilization \\\n"
                f"  --dimensions Name=InstanceId,Value={resource_id} \\\n"
                "  --start-time $(date -v-7d +%Y-%m-%dT%H:%M:%S) \\\n"
                "  --end-time $(date +%Y-%m-%dT%H:%M:%S) \\\n"
                "  --period 3600 --statistics Average Maximum"
            ),
            "rds": (
                f"aws cloudwatch get-metric-statistics --namespace AWS/RDS \\\n"
                f"  --metric-name CPUUtilization \\\n"
                f"  --dimensions Name=DBInstanceIdentifier,Value={resource_id} \\\n"
                "  --start-time $(date -v-7d +%Y-%m-%dT%H:%M:%S) \\\n"
                "  --end-time $(date +%Y-%m-%dT%H:%M:%S) \\\n"
                "  --period 3600 --statistics Average"
            ),
            "lambda": (
                f"aws cloudwatch get-metric-statistics --namespace AWS/Lambda \\\n"
                f"  --metric-name Duration \\\n"
                f"  --dimensions Name=FunctionName,Value={resource_id} \\\n"
                "  --start-time $(date -v-7d +%Y-%m-%dT%H:%M:%S) \\\n"
                "  --end-time $(date +%Y-%m-%dT%H:%M:%S) \\\n"
                "  --period 3600 --statistics Average p99"
            ),
        }
        example = examples.get(
            service,
            (f"aws cloudwatch get-metric-statistics --namespace AWS/{service.upper()} \\\n  --dimensions Name=ResourceId,Value={resource_id}"),
        )

        return f"""Analyze performance of {service} resource {resource_id}.

Example:
{example}

Gather: CPU, memory, I/O, latency metrics over past 7 days.
Identify: bottlenecks, right-sizing opportunities, configuration optimizations.
Output: metric gathering commands, then specific tuning recommendations with commands."""

    @mcp.prompt(
        name="multi_account_governance",
        description="Generate AWS CLI commands for Organizations/Control Tower setup",
    )
    def multi_account_governance(account_type: str = "organization") -> str:
        """Generate multi-account governance commands."""
        return """Set up multi-account governance with AWS Organizations.

Example:
aws organizations create-organizational-unit --parent-id r-xxxx --name Workloads
aws organizations create-policy --name DenyRootUser \\
  --type SERVICE_CONTROL_POLICY --content file://deny-root-scp.json
aws organizations attach-policy --policy-id p-xxxx --target-id ou-xxxx

Include: OU structure (Security, Workloads, Sandbox), SCPs for guardrails, centralized logging setup.
Output: commands to create OUs, attach SCPs, enable trusted access for Security Hub/Config."""

    logger.info("Successfully registered all AWS prompt templates")
