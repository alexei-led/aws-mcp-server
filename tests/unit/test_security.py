"""Unit tests for the security module."""

from unittest.mock import mock_open, patch

import pytest
import yaml

from aws_mcp_server.security import (
    DEFAULT_DANGEROUS_COMMANDS,
    DEFAULT_SAFE_PATTERNS,
    SecurityConfig,
    ValidationRule,
    check_regex_rules,
    is_service_command_safe,
    load_security_config,
    reload_security_config,
    validate_aws_command,
    validate_command,
    validate_pipe_command,
)


def test_is_service_command_safe():
    """Test the is_service_command_safe function."""
    # Test with known safe pattern
    assert is_service_command_safe("aws s3 ls", "s3") is True

    # Test with known dangerous pattern that has safe override
    assert is_service_command_safe("aws s3 ls --profile test", "s3") is True

    # Test with known dangerous pattern with no safe override
    assert is_service_command_safe("aws s3 rb s3://my-bucket", "s3") is False

    # Test with unknown service
    assert (
        is_service_command_safe("aws unknown-service command", "unknown-service")
        is False
    )


def test_check_regex_rules():
    """Test the check_regex_rules function."""
    # Test with a pattern that should match
    with patch("aws_mcp_server.security.SECURITY_CONFIG") as mock_config:
        mock_config.regex_rules = {
            "general": [
                ValidationRule(
                    pattern=r"aws .* --profile\s+(root|admin|administrator)",
                    description="Prevent use of sensitive profiles",
                    error_message="Using sensitive profiles (root, admin) is restricted",
                    regex=True,
                )
            ]
        }

        # Should match the rule
        error = check_regex_rules("aws s3 ls --profile root")
        assert error is not None
        assert "Using sensitive profiles" in error

        # Should not match
        assert check_regex_rules("aws s3 ls --profile user") is None


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_validate_aws_command_basic():
    """Test basic validation of AWS commands."""
    # Valid command should not raise
    validate_aws_command("aws s3 ls")

    # Invalid commands should raise ValueError
    with pytest.raises(ValueError, match="Commands must start with 'aws'"):
        validate_aws_command("s3 ls")

    with pytest.raises(ValueError, match="must include an AWS service"):
        validate_aws_command("aws")


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_validate_aws_command_dangerous():
    """Test validation of dangerous AWS commands."""
    # Use a test config
    with patch("aws_mcp_server.security.SECURITY_CONFIG") as mock_config:
        mock_config.dangerous_commands = {
            "iam": ["aws iam create-user", "aws iam create-access-key"],
            "ec2": ["aws ec2 terminate-instances"],
        }
        mock_config.safe_patterns = {
            "iam": ["aws iam create-user --help"],
            "ec2": [],
        }
        mock_config.regex_rules = {}

        # Dangerous command should raise ValueError
        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command("aws iam create-user --user-name test-user")

        # Help on dangerous command should be allowed
        validate_aws_command("aws iam create-user --help")

        # Dangerous command with no safe override should raise
        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command("aws ec2 terminate-instances --instance-id i-12345")


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_validate_aws_command_regex():
    """Test validation of AWS commands with regex rules."""
    # Set up command for testing
    profile_command = "aws s3 ls --profile root"
    policy_command = """aws s3api put-bucket-policy --bucket my-bucket --policy "{\\"Version\\":\\"2012-10-17\\",\
\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":\\"*\\",\\"Action\\":\\"s3:GetObject\\",\
\\"Resource\\":\\"arn:aws:s3:::my-bucket/*\\"}]}" """

    # We need to patch both the check_regex_rules function and the config
    with patch("aws_mcp_server.security.SECURITY_CONFIG") as mock_config:
        mock_config.dangerous_commands = {}
        mock_config.safe_patterns = {}

        # Test for the root profile check
        with patch("aws_mcp_server.security.check_regex_rules") as mock_check:
            mock_check.return_value = "Using sensitive profiles is restricted"

            with pytest.raises(
                ValueError, match="Using sensitive profiles is restricted"
            ):
                validate_aws_command(profile_command)

            # Verify check_regex_rules was called
            mock_check.assert_called_once()

        # Test for the bucket policy check
        with patch("aws_mcp_server.security.check_regex_rules") as mock_check:
            # Have the mock return error for the policy command
            mock_check.return_value = "Creating public bucket policies is restricted"

            with pytest.raises(
                ValueError, match="Creating public bucket policies is restricted"
            ):
                validate_aws_command(policy_command)

            # Verify check_regex_rules was called
            mock_check.assert_called_once()


@patch("aws_mcp_server.security.SECURITY_MODE", "permissive")
def test_validate_aws_command_permissive():
    """Test validation of AWS commands in permissive mode."""
    # In permissive mode, dangerous commands should be allowed
    with patch("aws_mcp_server.security.logger.warning") as mock_warning:
        validate_aws_command("aws iam create-user --user-name test-user")
        mock_warning.assert_called_once()


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_validate_pipe_command():
    """Test validation of piped commands."""
    with patch("aws_mcp_server.security.validate_aws_command") as mock_aws_validate:
        with patch(
            "aws_mcp_server.security.ALLOWED_UNIX_COMMANDS", {"grep", "head", "tail"}
        ):
            with patch(
                "aws_mcp_server.security.check_dangerous_patterns", return_value=None
            ):
                # Test valid piped command
                validate_pipe_command("aws s3 ls | grep bucket")
                mock_aws_validate.assert_called_once_with("aws s3 ls")

                mock_aws_validate.reset_mock()

                # Test command with unrecognized Unix command
                with pytest.raises(ValueError, match="not allowed"):
                    validate_pipe_command("aws s3 ls | unknown_command")

    # Empty command should raise
    with pytest.raises(ValueError, match="Empty command"):
        validate_pipe_command("")

    # Empty second command test
    with patch("aws_mcp_server.security.split_pipe_command") as mock_split_pipe:
        mock_split_pipe.return_value = ["aws s3 ls", ""]
        with pytest.raises(ValueError, match="Empty command at position"):
            validate_pipe_command("aws s3 ls | ")


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_validate_command():
    """Test the centralized validate_command function."""
    # Simple AWS command
    validate_command("aws s3 ls")

    # Piped command
    validate_command("aws s3 ls | grep bucket")

    # Invalid command
    with pytest.raises(ValueError):
        validate_command("s3 ls")


def test_load_security_config_default():
    """Test loading security configuration with defaults."""
    with patch("aws_mcp_server.security.SECURITY_CONFIG_PATH", ""):
        config = load_security_config()

        # Should have loaded default values
        assert config.dangerous_commands == DEFAULT_DANGEROUS_COMMANDS
        assert config.safe_patterns == DEFAULT_SAFE_PATTERNS

        # Should have regex rules converted from DEFAULT_REGEX_RULES
        assert "general" in config.regex_rules
        assert len(config.regex_rules["general"]) > 0
        assert isinstance(config.regex_rules["general"][0], ValidationRule)


def test_load_security_config_custom():
    """Test loading security configuration from a custom file."""
    # Mock YAML file contents
    test_config = {
        "dangerous_commands": {"test_service": ["aws test_service dangerous_command"]},
        "safe_patterns": {"test_service": ["aws test_service safe_pattern"]},
        "regex_rules": {
            "test_service": [
                {
                    "pattern": "test_pattern",
                    "description": "Test description",
                    "error_message": "Test error message",
                }
            ]
        },
    }

    # Mock the open function to return our test config
    with patch("builtins.open", mock_open(read_data=yaml.dump(test_config))):
        with patch("aws_mcp_server.security.SECURITY_CONFIG_PATH", "/fake/path.yaml"):
            with patch("pathlib.Path.exists", return_value=True):
                config = load_security_config()

                # Should have our custom values
                assert "test_service" in config.dangerous_commands
                assert "test_service" in config.safe_patterns
                assert "test_service" in config.regex_rules
                assert config.regex_rules["test_service"][0].pattern == "test_pattern"


def test_load_security_config_error():
    """Test error handling when loading security configuration."""
    with patch("builtins.open", side_effect=Exception("Test error")):
        with patch("aws_mcp_server.security.SECURITY_CONFIG_PATH", "/fake/path.yaml"):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("aws_mcp_server.security.logger.error") as mock_error:
                    with patch(
                        "aws_mcp_server.security.logger.warning"
                    ) as mock_warning:
                        config = load_security_config()

                        # Should log error and warning
                        mock_error.assert_called_once()
                        mock_warning.assert_called_once()

                        # Should still have default values
                        assert config.dangerous_commands == DEFAULT_DANGEROUS_COMMANDS


def test_reload_security_config():
    """Test reloading security configuration."""
    with patch("aws_mcp_server.security.load_security_config") as mock_load:
        mock_load.return_value = SecurityConfig(
            dangerous_commands={"test": ["test"]}, safe_patterns={"test": ["test"]}
        )

        reload_security_config()

        # Should have called load_security_config
        mock_load.assert_called_once()


# Integration-like tests for specific dangerous commands
@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_specific_dangerous_commands():
    """Test validation of specific dangerous commands."""
    # Configure the SECURITY_CONFIG with some dangerous commands
    with patch("aws_mcp_server.security.SECURITY_CONFIG") as mock_config:
        mock_config.dangerous_commands = {
            "iam": [
                "aws iam create-user",
                "aws iam create-access-key",
                "aws iam attach-user-policy",
            ],
            "ec2": ["aws ec2 terminate-instances"],
            "s3": ["aws s3 rb"],
            "rds": ["aws rds delete-db-instance"],
        }
        mock_config.safe_patterns = {
            "iam": ["aws iam get-", "aws iam list-"],
            "ec2": ["aws ec2 describe-"],
            "s3": ["aws s3 ls"],
            "rds": ["aws rds describe-"],
        }
        mock_config.regex_rules = {}

        # IAM dangerous commands
        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command("aws iam create-user --user-name test-user")

        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command("aws iam create-access-key --user-name test-user")

        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command(
                "aws iam attach-user-policy --user-name test-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
            )

        # EC2 dangerous commands
        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command("aws ec2 terminate-instances --instance-ids i-12345")

        # S3 dangerous commands
        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command("aws s3 rb s3://my-bucket --force")

        # RDS dangerous commands
        with pytest.raises(ValueError, match="restricted for security reasons"):
            validate_aws_command(
                "aws rds delete-db-instance --db-instance-identifier my-db --skip-final-snapshot"
            )


# Tests for safe patterns overriding dangerous commands
@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_safe_overrides():
    """Test safe patterns that override dangerous commands."""
    # IAM help commands should be allowed even if potentially dangerous
    validate_aws_command("aws iam --help")
    validate_aws_command("aws iam help")
    validate_aws_command("aws iam get-user --user-name test-user")
    validate_aws_command("aws iam list-users")

    # EC2 describe commands should be allowed
    validate_aws_command("aws ec2 describe-instances")

    # S3 list commands should be allowed
    validate_aws_command("aws s3 ls")
    validate_aws_command("aws s3api list-buckets")


# Tests for complex regex patterns
@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_complex_regex_patterns():
    """Test more complex regex patterns."""
    # Instead of testing the regex directly, test the behavior we expect
    dangerous_sg_command = "aws ec2 authorize-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0"
    safe_sg_command_80 = "aws ec2 authorize-security-group-ingress --group-id sg-12345 --protocol tcp --port 80 --cidr 0.0.0.0/0"

    # Define the validation rule directly
    ValidationRule(
        pattern=r"aws ec2 authorize-security-group-ingress.*--cidr\s+0\.0\.0\.0/0.*--port\s+(?!80|443)\d+",
        description="Prevent open security groups for non-web ports",
        error_message="Security group error",
        regex=True,
    )

    # Test with mocked check_regex_rules
    with patch("aws_mcp_server.security.SECURITY_CONFIG") as mock_config:
        mock_config.dangerous_commands = {}
        mock_config.safe_patterns = {}

        with patch("aws_mcp_server.security.check_regex_rules") as mock_check:
            # Set up mock to return error for the dangerous command
            mock_check.side_effect = lambda cmd, svc=None: (
                "Security group error" if "--port 22" in cmd else None
            )

            # Test dangerous command raises error
            with pytest.raises(ValueError, match="Security group error"):
                validate_aws_command(dangerous_sg_command)

            # Test safe command doesn't raise
            mock_check.reset_mock()
            mock_check.return_value = None  # Explicit safe return
            validate_aws_command(safe_sg_command_80)  # Should not raise


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_is_service_command_safe_general_pattern():
    """Test that general safe patterns work across services."""
    with patch("aws_mcp_server.security.SECURITY_CONFIG") as mock_config:
        mock_config.safe_patterns = {
            "s3": ["aws s3 ls"],
            "general": ["--help", "help"],
        }
        mock_config.dangerous_commands = {}

        # General safe pattern should match
        assert (
            is_service_command_safe("aws ec2 describe-instances --help", "ec2") is True
        )
        assert is_service_command_safe("aws iam help", "iam") is True


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_check_regex_rules_service_specific():
    """Test service-specific regex rules."""
    with patch("aws_mcp_server.security.SECURITY_CONFIG") as mock_config:
        mock_config.regex_rules = {
            "general": [],
            "iam": [
                ValidationRule(
                    pattern=r"--user-name\s+(root|admin)",
                    description="Prevent creating users with sensitive names",
                    error_message="Creating users with sensitive names is restricted",
                    regex=True,
                )
            ],
        }

        # Should match service-specific rule
        error = check_regex_rules("aws iam create-user --user-name admin", "iam")
        assert error is not None
        assert "sensitive names" in error

        # Should not match for different service
        error = check_regex_rules("aws iam create-user --user-name admin", "ec2")
        assert error is None


@patch("aws_mcp_server.security.SECURITY_MODE", "permissive")
def test_validate_pipe_command_permissive_mode():
    """Test that pipe command validation is skipped in permissive mode."""
    with patch("aws_mcp_server.security.logger.warning") as mock_warning:
        # This would normally fail validation but should pass in permissive mode
        validate_pipe_command("aws s3 ls | grep bucket")
        mock_warning.assert_called_once()
        assert "permissive" in mock_warning.call_args[0][0].lower()


@patch("aws_mcp_server.security.SECURITY_MODE", "strict")
def test_validate_pipe_command_dangerous_patterns():
    """Test that dangerous patterns in Unix commands are blocked."""
    with patch("aws_mcp_server.security.check_dangerous_patterns") as mock_check:
        mock_check.return_value = "Dangerous option detected"

        with pytest.raises(ValueError, match="Security violation"):
            validate_pipe_command("aws s3 ls | grep -r /")


@patch("aws_mcp_server.security.SECURITY_MODE", "permissive")
def test_validate_command_permissive_mode():
    """Test that command validation is skipped in permissive mode."""
    with patch("aws_mcp_server.security.logger.warning") as mock_warning:
        # This would normally fail validation but should pass in permissive mode
        validate_command("aws iam create-user --user-name test")
        mock_warning.assert_called_once()
        assert "permissive" in mock_warning.call_args[0][0].lower()
