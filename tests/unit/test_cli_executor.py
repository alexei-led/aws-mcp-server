"""Tests for the CLI executor module."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from aws_mcp_server.cli_executor import (
    CommandExecutionError,
    CommandValidationError,
    check_aws_cli_installed,
    execute_aws_command,
    execute_pipe_command,
    get_command_help,
    is_auth_error,
)
from aws_mcp_server.config import MAX_OUTPUT_SIZE


@pytest.mark.asyncio
async def test_execute_aws_command_success():
    """Test successful command execution."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        # Mock a successful sandboxed execution
        mock_sandbox.return_value = (b"Success output", b"", 0)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "success"
        assert result["output"] == "Success output"
        mock_sandbox.assert_called_once()
        # Verify the command was passed correctly
        call_args = mock_sandbox.call_args
        assert call_args[0][0] == ["aws", "s3", "ls"]


@pytest.mark.asyncio
async def test_execute_aws_command_ec2_with_region_added():
    """Test that region is automatically added to EC2 commands."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        # Mock a successful sandboxed execution
        mock_sandbox.return_value = (b"EC2 instances", b"", 0)

        # Import here to ensure the test uses the actual value
        from aws_mcp_server.config import AWS_REGION

        # Execute an EC2 command without region
        result = await execute_aws_command("aws ec2 describe-instances")

        assert result["status"] == "success"
        assert result["output"] == "EC2 instances"

        # Verify region was added to the command
        mock_sandbox.assert_called_once()
        call_args = mock_sandbox.call_args[0][0]
        assert call_args[0] == "aws"
        assert call_args[1] == "ec2"
        assert call_args[2] == "describe-instances"
        assert "--region" in call_args
        assert AWS_REGION in call_args


@pytest.mark.asyncio
async def test_execute_aws_command_ec2_with_region_equals_syntax():
    """Test that region is NOT added when --region=value is already present."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"EC2 instances", b"", 0)

        # Execute an EC2 command with --region=value syntax
        result = await execute_aws_command("aws ec2 describe-instances --region=eu-west-1")

        assert result["status"] == "success"

        # Verify region was NOT added (user's region should be preserved)
        call_args = mock_sandbox.call_args[0][0]
        region_args = [arg for arg in call_args if arg.startswith("--region")]
        assert len(region_args) == 1  # Only the user's --region=eu-west-1
        assert region_args[0] == "--region=eu-west-1"


@pytest.mark.asyncio
async def test_execute_aws_command_with_custom_timeout():
    """Test command execution with custom timeout."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"Success output", b"", 0)

        # Use a custom timeout
        custom_timeout = 120
        await execute_aws_command("aws s3 ls", timeout=custom_timeout)

        # Check that the custom timeout was passed
        mock_sandbox.assert_called_once()
        call_kwargs = mock_sandbox.call_args[1]
        assert call_kwargs.get("timeout") == float(custom_timeout)


@pytest.mark.asyncio
async def test_execute_aws_command_error():
    """Test command execution error."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        # Mock a failed execution
        mock_sandbox.return_value = (b"", b"Error message", 1)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "error"
        assert result["output"] == "Error message"


@pytest.mark.asyncio
async def test_execute_aws_command_auth_error():
    """Test command execution with authentication error."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        # Mock a process that returns auth error
        mock_sandbox.return_value = (b"", b"Unable to locate credentials", 1)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "error"
        assert "Authentication error" in result["output"]
        assert "Unable to locate credentials" in result["output"]
        assert "Please check your AWS credentials" in result["output"]


@pytest.mark.asyncio
async def test_execute_aws_command_timeout():
    """Test command timeout."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        # Mock a timeout
        mock_sandbox.side_effect = asyncio.TimeoutError("Command timed out")

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_aws_command("aws s3 ls", timeout=1)

        # Check error message
        assert "Command timed out after 1 seconds" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_aws_command_general_exception():
    """Test handling of general exceptions during command execution."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.side_effect = Exception("Test exception")

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_aws_command("aws s3 ls")

        assert "Failed to execute command" in str(excinfo.value)
        assert "Test exception" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_aws_command_truncate_output():
    """Test truncation of large outputs."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        # Generate a large output that exceeds MAX_OUTPUT_SIZE
        large_output = "x" * (MAX_OUTPUT_SIZE + 1000)
        mock_sandbox.return_value = (large_output.encode("utf-8"), b"", 0)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "success"
        assert len(result["output"]) <= MAX_OUTPUT_SIZE + 100  # Allow for the truncation message
        assert "output truncated" in result["output"]


@pytest.mark.parametrize(
    "error_message,expected_result",
    [
        # Positive cases
        ("Unable to locate credentials", True),
        ("Some text before ExpiredToken and after", True),
        ("Error: AccessDenied when attempting to perform operation", True),
        ("AuthFailure: credentials could not be verified", True),
        ("The security token included in the request is invalid", True),
        ("The config profile could not be found", True),
        # Negative cases
        ("S3 bucket not found", False),
        ("Resource not found: myresource", False),
        ("Invalid parameter value", False),
    ],
)
def test_is_auth_error(error_message, expected_result):
    """Test the is_auth_error function with various error messages."""
    assert is_auth_error(error_message) == expected_result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "returncode,stdout,stderr,exception,expected_result",
    [
        # CLI installed
        (0, b"aws-cli/2.15.0", b"", None, True),
        # CLI not installed - command not found
        (127, b"", b"command not found", None, False),
        # CLI error case
        (1, b"", b"some error", None, False),
        # Exception during command execution
        (None, None, None, Exception("Test exception"), False),
    ],
)
async def test_check_aws_cli_installed(returncode, stdout, stderr, exception, expected_result):
    """Test check_aws_cli_installed function with various scenarios."""
    if exception:
        with patch("asyncio.create_subprocess_exec", side_effect=exception):
            result = await check_aws_cli_installed()
            assert result is expected_result
    else:
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_subprocess:
            process_mock = AsyncMock()
            process_mock.returncode = returncode
            process_mock.communicate.return_value = (stdout, stderr)
            mock_subprocess.return_value = process_mock

            result = await check_aws_cli_installed()
            assert result is expected_result

            if returncode == 0:  # Only verify call args for success case to avoid redundancy
                mock_subprocess.assert_called_once_with(
                    "aws",
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "service,command,mock_type,mock_value,expected_text,expected_call",
    [
        # Successful help retrieval with service and command
        (
            "s3",
            "ls",
            "return_value",
            {"status": "success", "output": "Help text"},
            "Help text",
            "aws s3 ls help",
        ),
        # Successful help retrieval with service only
        (
            "s3",
            None,
            "return_value",
            {"status": "success", "output": "Help text for service"},
            "Help text for service",
            "aws s3 help",
        ),
        # Error scenarios
        (
            "s3",
            "ls",
            "side_effect",
            CommandValidationError("Test validation error"),
            "Command validation error: Test validation error",
            None,
        ),
        (
            "s3",
            "ls",
            "side_effect",
            CommandExecutionError("Test execution error"),
            "Error retrieving help: Test execution error",
            None,
        ),
        (
            "s3",
            "ls",
            "side_effect",
            Exception("Test exception"),
            "Error retrieving help: Test exception",
            None,
        ),
        # Error result from AWS command
        (
            "s3",
            "ls",
            "return_value",
            {"status": "error", "output": "Command failed"},
            "Error: Command failed",
            "aws s3 ls help",
        ),
    ],
)
async def test_get_command_help(service, command, mock_type, mock_value, expected_text, expected_call):
    """Test get_command_help function with various scenarios."""
    with patch("aws_mcp_server.cli_executor.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        # Configure the mock based on the test case
        if mock_type == "return_value":
            mock_execute.return_value = mock_value
        else:  # side_effect
            mock_execute.side_effect = mock_value

        # Call the function
        result = await get_command_help(service, command)

        # Verify the result
        assert expected_text in result["help_text"]

        # Verify the mock was called correctly if expected_call is provided
        if expected_call:
            mock_execute.assert_called_once_with(expected_call)


@pytest.mark.asyncio
async def test_execute_aws_command_with_pipe():
    """Test execute_aws_command with a piped command."""
    # Test that execute_aws_command calls execute_pipe_command for piped commands
    with patch("aws_mcp_server.cli_executor.is_pipe_command", return_value=True):
        with patch("aws_mcp_server.cli_executor.execute_pipe_command", new_callable=AsyncMock) as mock_pipe_exec:
            mock_pipe_exec.return_value = {
                "status": "success",
                "output": "Piped result",
            }

            result = await execute_aws_command("aws s3 ls | grep bucket")

            assert result["status"] == "success"
            assert result["output"] == "Piped result"
            mock_pipe_exec.assert_called_once_with("aws s3 ls | grep bucket", None)


@pytest.mark.asyncio
async def test_execute_pipe_command_success():
    """Test successful execution of a pipe command."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command") as mock_validate:
        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.return_value = (b"Filtered results", b"", 0)

            result = await execute_pipe_command("aws s3 ls | grep bucket")

            assert result["status"] == "success"
            assert result["output"] == "Filtered results"
            mock_validate.assert_called_once_with("aws s3 ls | grep bucket")
            mock_sandbox.assert_called_once()


@pytest.mark.asyncio
async def test_execute_pipe_command_ec2_with_region_added():
    """Test that region is automatically added to EC2 commands in a pipe."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command"):
        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.return_value = (b"Filtered EC2 instances", b"", 0)

            # Import here to ensure the test uses the actual value
            from aws_mcp_server.config import AWS_REGION

            # Execute a piped EC2 command without region
            result = await execute_pipe_command("aws ec2 describe-instances | grep instance-id")

            assert result["status"] == "success"
            assert result["output"] == "Filtered EC2 instances"

            # Verify the command was modified to include region
            mock_sandbox.assert_called_once()
            call_args = mock_sandbox.call_args[0][0]
            # First command should have region added
            assert "--region" in call_args[0]
            assert AWS_REGION in call_args[0]


@pytest.mark.asyncio
async def test_execute_pipe_command_ec2_with_region_equals_syntax():
    """Test that region is NOT added when --region=value is already present in pipe."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command"):
        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.return_value = (b"Filtered EC2 instances", b"", 0)

            # Execute a piped EC2 command with --region=value syntax
            result = await execute_pipe_command("aws ec2 describe-instances --region=eu-west-1 | grep instance-id")

            assert result["status"] == "success"

            # Verify region was NOT added (user's region should be preserved)
            mock_sandbox.assert_called_once()
            call_args = mock_sandbox.call_args[0][0]
            # First command should only have the user's --region=eu-west-1
            region_args = [arg for arg in call_args[0] if arg.startswith("--region")]
            assert len(region_args) == 1
            assert region_args[0] == "--region=eu-west-1"


@pytest.mark.asyncio
async def test_execute_pipe_command_validation_error():
    """Test execute_pipe_command with validation error."""
    with patch(
        "aws_mcp_server.cli_executor.validate_pipe_command",
        side_effect=CommandValidationError("Invalid pipe command"),
    ):
        with pytest.raises(CommandValidationError) as excinfo:
            await execute_pipe_command("invalid | pipe | command")

        assert "Invalid pipe command" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_pipe_command_execution_error():
    """Test execute_pipe_command with execution error."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command"):
        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.side_effect = Exception("Execution error")

            with pytest.raises(CommandExecutionError) as excinfo:
                await execute_pipe_command("aws s3 ls | grep bucket")

            assert "Failed to execute piped command" in str(excinfo.value)
            assert "Execution error" in str(excinfo.value)


# New test cases to improve coverage


@pytest.mark.asyncio
async def test_execute_pipe_command_timeout():
    """Test timeout handling in piped commands."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command"):
        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            # Simulate timeout
            mock_sandbox.side_effect = asyncio.TimeoutError("Command timed out")

            with pytest.raises(CommandExecutionError) as excinfo:
                await execute_pipe_command("aws s3 ls | grep bucket")

            assert "Command timed out" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_pipe_command_with_custom_timeout():
    """Test piped command execution with custom timeout."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command"):
        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.return_value = (b"Piped output", b"", 0)

            custom_timeout = 120
            await execute_pipe_command("aws s3 ls | grep bucket", timeout=custom_timeout)

            # Verify the custom timeout was passed
            mock_sandbox.assert_called_once()
            call_kwargs = mock_sandbox.call_args[1]
            assert call_kwargs.get("timeout") == float(custom_timeout)


@pytest.mark.asyncio
async def test_execute_pipe_command_large_output():
    """Test handling of large output in piped commands."""
    with patch("aws_mcp_server.cli_executor.validate_pipe_command"):
        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            # Generate large output that would be truncated
            large_output = "x" * (MAX_OUTPUT_SIZE + 1000)
            mock_sandbox.return_value = (large_output.encode("utf-8"), b"", 0)

            result = await execute_pipe_command("aws s3 ls | grep bucket")

            assert result["status"] == "success"
            # Output should be truncated
            assert len(result["output"]) <= MAX_OUTPUT_SIZE + 100
            assert "output truncated" in result["output"]


@pytest.mark.parametrize(
    "exit_code,stderr,expected_status,expected_msg",
    [
        (0, b"", "success", ""),  # Success case
        (
            1,
            b"Error: bucket not found",
            "error",
            "Error: bucket not found",
        ),  # Standard error
        (1, b"AccessDenied", "error", "Authentication error"),  # Auth error
        (
            0,
            b"Warning: deprecated feature",
            "success",
            "",
        ),  # Warning on stderr but success exit code
    ],
)
@pytest.mark.asyncio
async def test_execute_aws_command_exit_codes(exit_code, stderr, expected_status, expected_msg):
    """Test handling of different process exit codes and stderr output."""
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        stdout = b"Command output" if exit_code == 0 else b""
        mock_sandbox.return_value = (stdout, stderr, exit_code)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == expected_status
        if expected_status == "success":
            assert result["output"] == "Command output"
        else:
            assert expected_msg in result["output"]
