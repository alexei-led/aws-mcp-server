"""Security utilities for AWS MCP Server.

This module provides security validation for AWS CLI commands,
including validation of command structure, dangerous command detection,
and pipe command validation.
"""

import logging
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from aws_mcp_server.config import SECURITY_CONFIG_PATH, SECURITY_MODE
from aws_mcp_server.tools import (
    ALLOWED_UNIX_COMMANDS,
    check_dangerous_patterns,
    is_pipe_command,
    split_pipe_command,
)

logger = logging.getLogger(__name__)

# Default dictionary of potentially dangerous commands by security category
# Focus on commands that could lead to security incidents, privilege escalation,
# credential theft, or account takeover
DEFAULT_DANGEROUS_COMMANDS: Dict[str, List[str]] = {
    # Identity and Access Management - core of security
    "iam": [
        "aws iam create-user",  # Creating new users (potential backdoor accounts)
        "aws iam create-access-key",  # Creating credentials (could lead to credential theft)
        "aws iam attach-user-policy",  # Attaching policies to users (privilege escalation)
        "aws iam attach-role-policy",  # Attaching policies to roles (privilege escalation)
        "aws iam attach-group-policy",  # Attaching policies to groups (privilege escalation)
        "aws iam create-policy",  # Creating new policies (potentially overprivileged)
        "aws iam put-user-policy",  # Inline policies for users (privilege escalation)
        "aws iam put-role-policy",  # Inline policies for roles (privilege escalation)
        "aws iam put-group-policy",  # Inline policies for groups (privilege escalation)
        "aws iam create-login-profile",  # Creating console passwords (potential backdoor)
        "aws iam update-access-key",  # Updating access key status (credential management)
        "aws iam update-assume-role-policy",  # Changing who can assume a role
        "aws iam remove-role-from-instance-profile",  # Removing roles (privilege escalation)
        "aws iam update-role",  # Modifying role (privilege escalation)
        "aws iam create-virtual-mfa-device",  # Creating MFA devices
        "aws iam deactivate-mfa-device",  # Disabling MFA (security circumvention)
        "aws iam delete-",  # Any IAM delete operations (potential denial of service)
    ],
    # Security, Identity & Compliance services
    "organizations": [
        "aws organizations create-account",  # Creating accounts
        "aws organizations leave-organization",  # Leaving an organization
        "aws organizations remove-account-from-organization",  # Removing accounts
        "aws organizations disable-policy-type",  # Disabling policy enforcement
        "aws organizations create-policy",  # Creating organization policies
        "aws organizations attach-policy",  # Attaching organization policies
    ],
    "sts": [
        "aws sts assume-role",  # Assuming roles with potentially higher privileges
        "aws sts get-session-token",  # Getting session tokens
        "aws sts get-federation-token",  # Getting federated tokens
    ],
    "secretsmanager": [
        "aws secretsmanager put-secret-value",  # Changing secrets
        "aws secretsmanager update-secret",  # Updating secrets
        "aws secretsmanager delete-secret",  # Deleting secrets
        "aws secretsmanager restore-secret",  # Restoring deleted secrets
    ],
    "kms": [
        "aws kms schedule-key-deletion",  # Scheduling key deletion (potential data loss)
        "aws kms disable-key",  # Disabling keys (potential data loss)
        "aws kms create-grant",  # Creating grants (key access)
        "aws kms revoke-grant",  # Revoking grants (potential denial of service)
    ],
    # Audit & Logging services - tampering with these is critical
    "cloudtrail": [
        "aws cloudtrail delete-trail",  # Deleting audit trails
        "aws cloudtrail stop-logging",  # Stopping audit logging
        "aws cloudtrail update-trail",  # Modifying audit configurations
        "aws cloudtrail put-event-selectors",  # Changing what events are logged
    ],
    "cloudwatch": [
        "aws cloudwatch delete-alarms",  # Deleting security alarms
        "aws cloudwatch disable-alarm-actions",  # Disabling alarm actions
        "aws cloudwatch delete-dashboards",  # Deleting monitoring dashboards
    ],
    "config": [
        "aws configservice delete-configuration-recorder",  # Deleting config recording
        "aws configservice stop-configuration-recorder",  # Stopping config recording
        "aws configservice delete-delivery-channel",  # Deleting config delivery
        "aws configservice delete-remediation-configuration",  # Deleting auto-remediation
    ],
    "guardduty": [
        "aws guardduty delete-detector",  # Deleting threat detection
        "aws guardduty disable-organization-admin-account",  # Disabling central security
        "aws guardduty update-detector",  # Modifying threat detection
    ],
    # Network & Data security
    "ec2": [
        "aws ec2 authorize-security-group-ingress",  # Opening inbound network access
        "aws ec2 authorize-security-group-egress",  # Opening outbound network access
        "aws ec2 modify-instance-attribute",  # Changing security attributes
    ],
    "s3": [
        "aws s3api put-bucket-policy",  # Changing bucket permissions
        "aws s3api put-bucket-acl",  # Changing bucket ACLs
        "aws s3api delete-bucket-policy",  # Removing bucket policy protections
        "aws s3api delete-bucket-encryption",  # Removing encryption
        "aws s3api put-public-access-block",  # Changing public access settings
    ],
}

# Default dictionary of safe patterns that override dangerous commands
# These patterns explicitly allow read-only operations that are needed for normal use
DEFAULT_SAFE_PATTERNS: Dict[str, List[str]] = {
    # Universal safe patterns for any AWS service
    "general": [
        "--help",  # All help commands are safe
        "help",  # All help subcommands are safe
        "--version",  # Version information is safe
        "--dry-run",  # Dry run operations don't make changes
    ],
    # Identity and Access Management
    "iam": [
        "aws iam get-",  # Read-only IAM operations
        "aws iam list-",  # Listing IAM resources
        "aws iam generate-credential-report",  # Generate reports (no security impact)
        "aws iam generate-service-last-accessed-details",  # Generate access reports
        "aws iam simulate-custom-policy",  # Policy simulation (no changes)
        "aws iam simulate-principal-policy",  # Policy simulation (no changes)
    ],
    # Security, Identity & Compliance services
    "organizations": [
        "aws organizations describe-",  # Read-only Organizations operations
        "aws organizations list-",  # Listing Organization resources
    ],
    "sts": [
        "aws sts get-caller-identity",  # Checking current identity (safe)
        "aws sts decode-authorization-message",  # Decoding error messages (safe)
    ],
    "secretsmanager": [
        "aws secretsmanager get-",  # Reading secrets (note: still sensitive)
        "aws secretsmanager list-",  # Listing secrets
        "aws secretsmanager describe-",  # Reading metadata about secrets
    ],
    "kms": [
        "aws kms describe-",  # Reading key metadata
        "aws kms get-",  # Getting key information
        "aws kms list-",  # Listing keys
    ],
    # Audit & Logging services
    "cloudtrail": [
        "aws cloudtrail describe-",  # Reading trail info
        "aws cloudtrail get-",  # Getting trail settings
        "aws cloudtrail list-",  # Listing trails
        "aws cloudtrail lookup-events",  # Searching events (read-only)
    ],
    "cloudwatch": [
        "aws cloudwatch describe-",  # Reading alarm info
        "aws cloudwatch get-",  # Getting metric data
        "aws cloudwatch list-",  # Listing metrics and alarms
    ],
    "config": [
        "aws configservice describe-",  # Reading configuration info
        "aws configservice get-",  # Getting config data
        "aws configservice list-",  # Listing config resources
        "aws configservice select-resource-config",  # Querying config (read-only)
    ],
    "guardduty": [
        "aws guardduty describe-",  # Reading detector info
        "aws guardduty get-",  # Getting findings and settings
        "aws guardduty list-",  # Listing GuardDuty resources
    ],
    # Network & Data security
    "ec2": [
        "aws ec2 describe-",  # All EC2 describe operations
        "aws ec2 get-",  # All EC2 get operations
        # Network security specific commands
        "aws ec2 describe-security-groups",  # Reading security group configurations
        "aws ec2 describe-network-acls",  # Reading network ACL configurations
    ],
    "s3": [
        "aws s3 ls",  # Listing buckets or objects (read-only)
        "aws s3api get-",  # All S3 API get operations (read-only)
        "aws s3api list-",  # All S3 API list operations (read-only)
        "aws s3api head-",  # All S3 API head operations (read-only)
        # Security-specific S3 operations
        "aws s3api get-bucket-policy",  # Reading bucket policies
        "aws s3api get-bucket-encryption",  # Reading encryption settings
        "aws s3api get-public-access-block",  # Reading public access settings
    ],
}

# Default regex patterns for more complex rules that cannot be easily captured
# with simple command prefix matching
DEFAULT_REGEX_RULES: Dict[str, List[Dict[str, str]]] = {
    # Security patterns that apply to all AWS services
    "general": [
        # Identity and Authentication Risks
        {
            "pattern": r"aws .* --profile\s+(root|admin|administrator)",
            "description": "Prevent use of sensitive profiles",
            "error_message": "Using sensitive profiles (root, admin) is restricted for security reasons.",
        },
        # Protocol and Encryption Risks
        {
            "pattern": r"aws .* --no-verify-ssl",
            "description": "Prevent disabling SSL verification",
            "error_message": "Disabling SSL verification is not allowed for security reasons.",
        },
        {
            "pattern": r"aws .* --output\s+text\s+.*--query\s+.*Password",
            "description": "Prevent password exposure in text output",
            "error_message": "Outputting sensitive data like passwords in text format is restricted.",
        },
        # Parameter security
        {
            "pattern": r"aws .* --debug",
            "description": "Prevent debug mode which shows sensitive info",
            "error_message": "Debug mode is restricted as it may expose sensitive information.",
        },
    ],
    # IAM-specific security patterns
    "iam": [
        # Privileged user creation
        {
            "pattern": r"aws iam create-user.*--user-name\s+(root|admin|administrator|backup|security|finance|billing)",
            "description": "Prevent creation of privileged-sounding users",
            "error_message": "Creating users with sensitive names is restricted for security reasons.",
        },
        # Privilege escalation via policies
        {
            "pattern": r"aws iam attach-user-policy.*--policy-arn\s+.*Administrator",
            "description": "Prevent attaching Administrator policies",
            "error_message": "Attaching Administrator policies is restricted for security reasons.",
        },
        {
            "pattern": r"aws iam attach-user-policy.*--policy-arn\s+.*FullAccess",
            "description": "Prevent attaching FullAccess policies to users",
            "error_message": "Attaching FullAccess policies directly to users is restricted (use roles instead).",
        },
        {
            "pattern": r"aws iam create-policy.*\"Effect\":\s*\"Allow\".*\"Action\":\s*\"\*\".*\"Resource\":\s*\"\*\"",
            "description": "Prevent creation of policies with * permissions",
            "error_message": "Creating policies with unrestricted (*) permissions is not allowed.",
        },
        # Password and access key controls
        {
            "pattern": r"aws iam create-login-profile.*--password-reset-required\s+false",
            "description": "Enforce password reset for new profiles",
            "error_message": "Creating login profiles without requiring password reset is restricted.",
        },
        {
            "pattern": r"aws iam update-account-password-policy.*--require-uppercase-characters\s+false",
            "description": "Prevent weakening password policies",
            "error_message": "Weakening account password policies is restricted.",
        },
    ],
    # Data security patterns
    "s3": [
        # Public access risks
        {
            "pattern": r"aws s3api put-bucket-policy.*\"Effect\":\s*\"Allow\".*\"Principal\":\s*\"\*\"",
            "description": "Prevent public bucket policies",
            "error_message": "Creating public bucket policies is restricted for security reasons.",
        },
        {
            "pattern": r"aws s3api put-public-access-block.*--public-access-block-configuration\s+.*\"BlockPublicAcls\":\s*false",
            "description": "Prevent disabling public access blocks",
            "error_message": "Disabling S3 public access blocks is restricted for security reasons.",
        },
        # Encryption risks
        {
            "pattern": r"aws s3api create-bucket.*--region\s+(?!eu|us-east-1).*--acl\s+public",
            "description": "Prevent public buckets outside of allowed regions",
            "error_message": "Creating public buckets outside allowed regions is restricted.",
        },
    ],
    # Network security patterns
    "ec2": [
        # Network exposure risks
        {
            "pattern": r"aws ec2 authorize-security-group-ingress.*--cidr\s+0\.0\.0\.0/0.*--port\s+(?!80|443)[0-9]+",
            "description": "Prevent open security groups for non-web ports",
            "error_message": "Opening non-web ports (other than 80/443) to the entire internet (0.0.0.0/0) is restricted.",
        },
        {
            "pattern": r"aws ec2 run-instances.*--user-data\s+.*curl.*\|.*sh",
            "description": "Detect potentially unsafe user-data scripts",
            "error_message": "Running scripts from remote sources in user-data presents security risks.",
        },
    ],
    # Logging and monitoring integrity
    "cloudtrail": [
        {
            "pattern": r"aws cloudtrail update-trail.*--no-include-global-service-events",
            "description": "Prevent disabling global event logging",
            "error_message": "Disabling CloudTrail logging for global service events is restricted.",
        },
        {
            "pattern": r"aws cloudtrail update-trail.*--no-multi-region",
            "description": "Prevent making trails single-region",
            "error_message": "Changing CloudTrail trails from multi-region to single-region is restricted.",
        },
    ],
}


@dataclass
class ValidationRule:
    """Represents a command validation rule."""

    pattern: str
    description: str
    error_message: str
    regex: bool = False


@dataclass
class SecurityConfig:
    """Security configuration for command validation."""

    dangerous_commands: Dict[str, List[str]]
    safe_patterns: Dict[str, List[str]]
    regex_rules: Dict[str, List[ValidationRule]] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize default values."""
        if not self.regex_rules:
            self.regex_rules = {}


def load_security_config() -> SecurityConfig:
    """Load security configuration from YAML file or use defaults.

    Returns:
        SecurityConfig object with loaded configuration
    """
    dangerous_commands = DEFAULT_DANGEROUS_COMMANDS.copy()
    safe_patterns = DEFAULT_SAFE_PATTERNS.copy()
    regex_rules = {}

    # Load default regex rules
    for category, rules in DEFAULT_REGEX_RULES.items():
        regex_rules[category] = []
        for rule in rules:
            regex_rules[category].append(
                ValidationRule(
                    pattern=rule["pattern"],
                    description=rule["description"],
                    error_message=rule["error_message"],
                    regex=True,
                )
            )

    # Load custom configuration if provided
    if SECURITY_CONFIG_PATH:
        config_path = Path(SECURITY_CONFIG_PATH)
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config_data = yaml.safe_load(f)

                # Update dangerous commands
                if "dangerous_commands" in config_data:
                    for service, commands in config_data["dangerous_commands"].items():
                        dangerous_commands[service] = commands

                # Update safe patterns
                if "safe_patterns" in config_data:
                    for service, patterns in config_data["safe_patterns"].items():
                        safe_patterns[service] = patterns

                # Load custom regex rules
                if "regex_rules" in config_data:
                    for category, rules in config_data["regex_rules"].items():
                        if category not in regex_rules:
                            regex_rules[category] = []

                        for rule in rules:
                            regex_rules[category].append(
                                ValidationRule(
                                    pattern=rule["pattern"],
                                    description=rule["description"],
                                    error_message=rule.get("error_message", f"Command matches restricted pattern: {rule['pattern']}"),
                                    regex=True,
                                )
                            )

                logger.info(f"Loaded security configuration from {config_path}")
            except Exception as e:
                logger.error(f"Error loading security configuration: {str(e)}")
                logger.warning("Using default security configuration")

    return SecurityConfig(dangerous_commands=dangerous_commands, safe_patterns=safe_patterns, regex_rules=regex_rules)


# Initialize security configuration
SECURITY_CONFIG = load_security_config()


def is_service_command_safe(command: str, service: str) -> bool:
    """Check if a command for a specific service is safe.

    This checks if a command that might match a dangerous pattern
    also matches a safe pattern, which would override the dangerous check.

    The function checks both:
    1. Service-specific safe patterns (e.g., "aws iam list-")
    2. General safe patterns that apply to any service (e.g., "--help")

    Args:
        command: The command to check
        service: The AWS service being used

    Returns:
        True if the command is safe, False otherwise
    """
    # First check service-specific safe patterns
    if service in SECURITY_CONFIG.safe_patterns:
        # Check if the command matches any safe pattern for this service
        for safe_pattern in SECURITY_CONFIG.safe_patterns[service]:
            if command.startswith(safe_pattern):
                logger.debug(f"Command matches service-specific safe pattern: {safe_pattern}")
                return True

    # Then check general safe patterns that apply to all services
    if "general" in SECURITY_CONFIG.safe_patterns:
        for safe_pattern in SECURITY_CONFIG.safe_patterns["general"]:
            if safe_pattern in command:
                logger.debug(f"Command matches general safe pattern: {safe_pattern}")
                return True

    return False


def check_regex_rules(command: str, service: Optional[str] = None) -> Optional[str]:
    """Check command against regex rules.

    Args:
        command: The command to check
        service: The AWS service being used, if known

    Returns:
        Error message if command matches a regex rule, None otherwise
    """
    # Check general rules that apply to all commands
    if "general" in SECURITY_CONFIG.regex_rules:
        for rule in SECURITY_CONFIG.regex_rules["general"]:
            pattern = re.compile(rule.pattern)
            if pattern.search(command):
                logger.warning(f"Command matches regex rule: {rule.description}")
                return rule.error_message

    # Check service-specific rules if service is provided
    if service and service in SECURITY_CONFIG.regex_rules:
        for rule in SECURITY_CONFIG.regex_rules[service]:
            pattern = re.compile(rule.pattern)
            if pattern.search(command):
                logger.warning(f"Command matches service-specific regex rule for {service}: {rule.description}")
                return rule.error_message

    return None


def validate_aws_command(command: str) -> None:
    """Validate that the command is a proper AWS CLI command.

    Args:
        command: The AWS CLI command to validate

    Raises:
        ValueError: If the command is invalid
    """
    logger.debug(f"Validating AWS command: {command}")

    # Skip validation in permissive mode
    if SECURITY_MODE.lower() == "permissive":
        logger.warning(f"Running in permissive security mode, skipping validation for: {command}")
        return

    # Basic validation
    cmd_parts = shlex.split(command)
    if not cmd_parts or cmd_parts[0].lower() != "aws":
        raise ValueError("Commands must start with 'aws'")

    if len(cmd_parts) < 2:
        raise ValueError("Command must include an AWS service (e.g., aws s3)")

    # Get the service from the command
    service = cmd_parts[1].lower()

    # Check regex rules first (these apply regardless of service)
    error_message = check_regex_rules(command, service)
    if error_message:
        raise ValueError(error_message)

    # Check against dangerous commands for this service
    if service in SECURITY_CONFIG.dangerous_commands:
        # Check each dangerous command pattern
        for dangerous_cmd in SECURITY_CONFIG.dangerous_commands[service]:
            if command.startswith(dangerous_cmd):
                # If it's a dangerous command, check if it's also in safe patterns
                if is_service_command_safe(command, service):
                    return  # Command is safe despite matching dangerous pattern

                # Command is dangerous, raise an error
                raise ValueError(
                    f"This command ({dangerous_cmd}) is restricted for security reasons. "
                    f"Please use a more specific, read-only command or add 'help' or '--help' to see available options."
                )

    logger.debug(f"Command validation successful: {command}")


def validate_pipe_command(pipe_command: str) -> None:
    """Validate a command that contains pipes.

    This checks both AWS CLI commands and Unix commands within a pipe chain.

    Args:
        pipe_command: The piped command to validate

    Raises:
        ValueError: If any command in the pipe is invalid
    """
    logger.debug(f"Validating pipe command: {pipe_command}")

    # Skip validation in permissive mode
    if SECURITY_MODE.lower() == "permissive":
        logger.warning(f"Running in permissive security mode, skipping validation for: {pipe_command}")
        return

    commands = split_pipe_command(pipe_command)

    if not commands:
        raise ValueError("Empty command")

    # First command must be an AWS CLI command
    validate_aws_command(commands[0])

    # Subsequent commands should be valid Unix commands
    for i, cmd in enumerate(commands[1:], 1):
        cmd_parts = shlex.split(cmd)
        if not cmd_parts:
            raise ValueError(f"Empty command at position {i} in pipe")

        cmd_name = cmd_parts[0]

        # Check if command is in the allowed list
        if cmd_name not in ALLOWED_UNIX_COMMANDS:
            raise ValueError(f"Command '{cmd_name}' at position {i} in pipe is not allowed. Only AWS commands and basic Unix utilities are permitted.")

        # Check for dangerous patterns in the command
        dangerous_error = check_dangerous_patterns(cmd, cmd_name)
        if dangerous_error:
            raise ValueError(f"Security violation at position {i} in pipe: {dangerous_error}. This command option is blocked for security reasons.")

    logger.debug(f"Pipe command validation successful: {pipe_command}")


def reload_security_config() -> None:
    """Reload security configuration from file.

    This allows for dynamic reloading of security rules without restarting the server.
    """
    global SECURITY_CONFIG
    SECURITY_CONFIG = load_security_config()
    logger.info("Security configuration reloaded")


def validate_command(command: str) -> None:
    """Centralized validation for all commands.

    This is the main entry point for command validation. The validation follows a multi-step process:

    1. Check if security validation should be skipped (permissive mode)
    2. Determine command type (piped or regular AWS command)
    3. For regular AWS commands:
       a. Verify basic structure (starts with 'aws' and has a service)
       b. Check against regex rules for complex patterns
       c. Check if it matches any dangerous command patterns
       d. If dangerous, check if it also matches any safe patterns
    4. For piped commands:
       a. Validate the AWS portion as above
       b. Validate that pipe targets are allowed Unix commands

    Args:
        command: The command to validate

    Raises:
        ValueError: If the command is invalid with a descriptive error message
    """
    logger.debug(f"Validating command: {command}")

    # Step 1: Skip validation in permissive mode
    if SECURITY_MODE.lower() == "permissive":
        logger.warning(f"Running in permissive security mode, skipping validation for: {command}")
        return

    # Step 2: Determine command type and validate accordingly
    if is_pipe_command(command):
        validate_pipe_command(command)
    else:
        validate_aws_command(command)

    logger.debug(f"Command validation successful: {command}")
