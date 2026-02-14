"""Tests for the CLI executor module."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from aws_mcp_server.cli_executor import (
    CommandExecutionError,
    check_aws_cli_installed,
    execute_aws_command,
    execute_pipe_command,
    format_error_message,
    get_command_help,
    is_auth_error,
)
from aws_mcp_server.config import MAX_OUTPUT_SIZE


@pytest.mark.asyncio
async def test_execute_aws_command_success():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"Success output", b"", 0)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "success"
        assert result["output"] == "Success output"
        mock_sandbox.assert_called_once()
        call_args = mock_sandbox.call_args
        assert call_args[0][0] == ["aws", "s3", "ls"]


@pytest.mark.asyncio
async def test_execute_aws_command_ec2_with_region_added():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"EC2 instances", b"", 0)

        from aws_mcp_server.config import AWS_REGION

        result = await execute_aws_command("aws ec2 describe-instances")

        assert result["status"] == "success"
        assert result["output"] == "EC2 instances"

        mock_sandbox.assert_called_once()
        call_args = mock_sandbox.call_args[0][0]
        assert call_args[0] == "aws"
        assert call_args[1] == "ec2"
        assert call_args[2] == "describe-instances"
        assert "--region" in call_args
        assert AWS_REGION in call_args


@pytest.mark.asyncio
async def test_execute_aws_command_ec2_with_region_equals_syntax():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"EC2 instances", b"", 0)

        result = await execute_aws_command("aws ec2 describe-instances --region=eu-west-1")

        assert result["status"] == "success"

        call_args = mock_sandbox.call_args[0][0]
        region_args = [arg for arg in call_args if arg.startswith("--region")]
        assert len(region_args) == 1
        assert region_args[0] == "--region=eu-west-1"


@pytest.mark.asyncio
async def test_execute_aws_command_with_custom_timeout():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"Success output", b"", 0)

        custom_timeout = 120
        await execute_aws_command("aws s3 ls", timeout=custom_timeout)

        mock_sandbox.assert_called_once()
        call_kwargs = mock_sandbox.call_args[1]
        assert call_kwargs.get("timeout") == float(custom_timeout)


@pytest.mark.asyncio
async def test_execute_aws_command_error():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"", b"Error message", 1)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "error"
        assert result["output"] == "Error message"


@pytest.mark.asyncio
async def test_execute_aws_command_auth_error():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.return_value = (b"", b"Unable to locate credentials", 1)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "error"
        assert "Authentication error" in result["output"]
        assert "Unable to locate credentials" in result["output"]
        assert "Please check your AWS credentials" in result["output"]


@pytest.mark.asyncio
async def test_execute_aws_command_timeout():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.side_effect = asyncio.TimeoutError("Command timed out")

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_aws_command("aws s3 ls", timeout=1)

        assert "Command timed out after 1s" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_aws_command_general_exception():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        mock_sandbox.side_effect = Exception("Test exception")

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_aws_command("aws s3 ls")

        assert "Failed to execute command" in str(excinfo.value)
        assert "Test exception" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_aws_command_truncate_output():
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        large_output = "x" * (MAX_OUTPUT_SIZE + 1000)
        mock_sandbox.return_value = (large_output.encode("utf-8"), b"", 0)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == "success"
        assert len(result["output"]) <= MAX_OUTPUT_SIZE + 100
        assert "output truncated" in result["output"]


@pytest.mark.asyncio
async def test_execute_aws_command_empty():
    with pytest.raises(CommandExecutionError, match="Empty command"):
        await execute_aws_command("")


@pytest.mark.parametrize(
    "error_message,expected_result",
    [
        ("Unable to locate credentials", True),
        ("Some text before ExpiredToken and after", True),
        ("Error: AccessDenied when attempting to perform operation", True),
        ("AuthFailure: credentials could not be verified", True),
        ("The security token included in the request is invalid", True),
        ("The config profile could not be found", True),
        ("S3 bucket not found", False),
        ("Resource not found: myresource", False),
        ("Invalid parameter value", False),
    ],
)
def test_is_auth_error(error_message, expected_result):
    assert is_auth_error(error_message) == expected_result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "returncode,stdout,stderr,exception,expected_result",
    [
        (0, b"aws-cli/2.15.0", b"", None, True),
        (127, b"", b"command not found", None, False),
        (1, b"", b"some error", None, False),
        (None, None, None, Exception("Test exception"), False),
    ],
)
async def test_check_aws_cli_installed(returncode, stdout, stderr, exception, expected_result):
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

            if returncode == 0:
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
        (
            "s3",
            "ls",
            "return_value",
            {"status": "success", "output": "Help text"},
            "Help text",
            "aws s3 ls help",
        ),
        (
            "s3",
            None,
            "return_value",
            {"status": "success", "output": "Help text for service"},
            "Help text for service",
            "aws s3 help",
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
    with patch("aws_mcp_server.cli_executor.execute_aws_command", new_callable=AsyncMock) as mock_execute:
        if mock_type == "return_value":
            mock_execute.return_value = mock_value
        else:
            mock_execute.side_effect = mock_value

        result = await get_command_help(service, command)

        assert expected_text in result["help_text"]

        if expected_call:
            mock_execute.assert_called_once_with(expected_call)


@pytest.mark.asyncio
async def test_execute_aws_command_with_pipe():
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
    with patch(
        "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
        new_callable=AsyncMock,
    ) as mock_sandbox:
        mock_sandbox.return_value = (b"Filtered results", b"", 0)

        result = await execute_pipe_command("aws s3 ls | grep bucket")

        assert result["status"] == "success"
        assert result["output"] == "Filtered results"
        mock_sandbox.assert_called_once()


@pytest.mark.asyncio
async def test_execute_pipe_command_ec2_with_region_added():
    with patch(
        "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
        new_callable=AsyncMock,
    ) as mock_sandbox:
        mock_sandbox.return_value = (b"Filtered EC2 instances", b"", 0)

        from aws_mcp_server.config import AWS_REGION

        result = await execute_pipe_command("aws ec2 describe-instances | grep instance-id")

        assert result["status"] == "success"
        assert result["output"] == "Filtered EC2 instances"

        mock_sandbox.assert_called_once()
        call_args = mock_sandbox.call_args[0][0]
        assert "--region" in call_args[0]
        assert AWS_REGION in call_args[0]


@pytest.mark.asyncio
async def test_execute_pipe_command_ec2_with_region_equals_syntax():
    with patch(
        "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
        new_callable=AsyncMock,
    ) as mock_sandbox:
        mock_sandbox.return_value = (b"Filtered EC2 instances", b"", 0)

        result = await execute_pipe_command("aws ec2 describe-instances --region=eu-west-1 | grep instance-id")

        assert result["status"] == "success"

        mock_sandbox.assert_called_once()
        call_args = mock_sandbox.call_args[0][0]
        region_args = [arg for arg in call_args[0] if arg.startswith("--region")]
        assert len(region_args) == 1
        assert region_args[0] == "--region=eu-west-1"


@pytest.mark.asyncio
async def test_execute_pipe_command_empty():
    with pytest.raises(CommandExecutionError, match="Empty command"):
        await execute_pipe_command("")


@pytest.mark.asyncio
async def test_execute_pipe_command_execution_error():
    with patch(
        "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
        new_callable=AsyncMock,
    ) as mock_sandbox:
        mock_sandbox.side_effect = Exception("Execution error")

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_pipe_command("aws s3 ls | grep bucket")

        assert "Failed to execute piped command" in str(excinfo.value)
        assert "Execution error" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_pipe_command_timeout():
    with patch(
        "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
        new_callable=AsyncMock,
    ) as mock_sandbox:
        mock_sandbox.side_effect = asyncio.TimeoutError("Command timed out")

        with pytest.raises(CommandExecutionError) as excinfo:
            await execute_pipe_command("aws s3 ls | grep bucket")

        assert "timed out" in str(excinfo.value)
        assert "increase the timeout parameter" in str(excinfo.value)


@pytest.mark.asyncio
async def test_execute_pipe_command_with_custom_timeout():
    with patch(
        "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
        new_callable=AsyncMock,
    ) as mock_sandbox:
        mock_sandbox.return_value = (b"Piped output", b"", 0)

        custom_timeout = 120
        await execute_pipe_command("aws s3 ls | grep bucket", timeout=custom_timeout)

        mock_sandbox.assert_called_once()
        call_kwargs = mock_sandbox.call_args[1]
        assert call_kwargs.get("timeout") == float(custom_timeout)


@pytest.mark.asyncio
async def test_execute_pipe_command_large_output():
    with patch(
        "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
        new_callable=AsyncMock,
    ) as mock_sandbox:
        large_output = "x" * (MAX_OUTPUT_SIZE + 1000)
        mock_sandbox.return_value = (large_output.encode("utf-8"), b"", 0)

        result = await execute_pipe_command("aws s3 ls | grep bucket")

        assert result["status"] == "success"
        assert len(result["output"]) <= MAX_OUTPUT_SIZE + 100
        assert "output truncated" in result["output"]


@pytest.mark.parametrize(
    "exit_code,stderr,expected_status,expected_msg",
    [
        (0, b"", "success", ""),
        (1, b"Error: bucket not found", "error", "Error: bucket not found"),
        (1, b"AccessDenied", "error", "Authentication error"),
        (0, b"Warning: deprecated feature", "success", ""),
    ],
)
@pytest.mark.asyncio
async def test_execute_aws_command_exit_codes(exit_code, stderr, expected_status, expected_msg):
    with patch("aws_mcp_server.cli_executor.execute_sandboxed_async", new_callable=AsyncMock) as mock_sandbox:
        stdout = b"Command output" if exit_code == 0 else b""
        mock_sandbox.return_value = (stdout, stderr, exit_code)

        result = await execute_aws_command("aws s3 ls")

        assert result["status"] == expected_status
        if expected_status == "success":
            assert result["output"] == "Command output"
        else:
            assert expected_msg in result["output"]


@pytest.mark.parametrize(
    "stderr,command,stdout,expected_hint",
    [
        ("", "aws s3 ls", "", "Command failed with no error output"),
        ("", "aws s3 ls", "Error from stdout", "Error from stdout"),
        ("bash: jq: command not found", "aws s3 ls | jq", "", "not installed"),
        ("invalid choice: 'xyz'", "aws s3 xyz", "", "aws_cli_help"),
        ("unknown command: xyz", "aws xyz", "", "aws_cli_help"),
        (
            "error: argument --bucket: missing required value",
            "aws s3 ls",
            "",
            "aws_cli_help",
        ),
        ("required argument --name", "aws lambda create-function", "", "aws_cli_help"),
        ("InvalidParameterValue: The value is not valid", "aws ec2 run", "", "values"),
        ("ValidationError: invalid parameter", "aws ec2 run", "", "values"),
        (
            "ResourceNotFoundException: Bucket does not exist",
            "aws s3 ls",
            "",
            "does not exist",
        ),
        ("NoSuchBucket: mybucket", "aws s3 ls", "", "does not exist"),
        ("ThrottlingException: Rate exceeded", "aws ec2", "", "rate limit"),
        ("Rate exceeded, please try again", "aws ec2", "", "rate limit"),
        ("Some random error message", "aws s3 ls", "", "Some random error message"),
    ],
)
def test_format_error_message(stderr, command, stdout, expected_hint):
    result = format_error_message(stderr, command, stdout)
    assert expected_hint in result


class TestAddEc2RegionIfNeeded:
    @pytest.mark.parametrize(
        "command,should_add_region",
        [
            ("aws ec2 describe-instances", True),
            ("aws ec2 run-instances --instance-type t2.micro", True),
            ("aws ec2 describe-instances --region us-west-2", False),
            ("aws ec2 describe-instances --region=us-west-2", False),
            ("aws s3 ls", False),
            ("aws lambda list-functions", False),
        ],
        ids=[
            "ec2_no_region",
            "ec2_with_other_args",
            "ec2_region_separate",
            "ec2_region_equals",
            "s3_no_change",
            "lambda_no_change",
        ],
    )
    def test_region_handling(self, command, should_add_region):
        from aws_mcp_server.cli_executor import _add_ec2_region_if_needed
        from aws_mcp_server.config import AWS_REGION

        result = _add_ec2_region_if_needed(command)

        if should_add_region:
            assert f"--region {AWS_REGION}" in result
        else:
            assert result == command


class TestProcessOutput:
    @pytest.mark.parametrize(
        "stdout,stderr,returncode,command,expected_status,output_check",
        [
            (b"Success", b"", 0, "aws s3 ls", "success", lambda o: o == "Success"),
            (b"", b"Error", 1, "aws s3 ls", "error", lambda o: "Error" in o),
            (
                b"",
                b"Unable to locate credentials",
                1,
                "aws s3 ls",
                "error",
                lambda o: "Authentication error" in o,
            ),
            (
                b"\xff\xfe",
                b"",
                0,
                "aws s3 ls",
                "success",
                lambda o: True,
            ),
            (
                b"Error from stdout",
                b"",
                1,
                "aws s3 ls",
                "error",
                lambda o: "Error from stdout" in o,
            ),
        ],
        ids=[
            "success_output",
            "error_output",
            "auth_error",
            "binary_decode_replace",
            "error_in_stdout",
        ],
    )
    def test_output_processing(self, stdout, stderr, returncode, command, expected_status, output_check):
        from aws_mcp_server.cli_executor import _process_output

        result = _process_output(stdout, stderr, returncode, command)

        assert result["status"] == expected_status
        assert output_check(result["output"])

    def test_output_truncation(self):
        from aws_mcp_server.cli_executor import _process_output

        large_output = ("x" * (MAX_OUTPUT_SIZE + 1000)).encode("utf-8")
        result = _process_output(large_output, b"", 0, "aws s3 ls")

        assert result["status"] == "success"
        assert len(result["output"]) <= MAX_OUTPUT_SIZE + 100
        assert "truncated" in result["output"]


class TestSandboxErrorHandling:
    @pytest.mark.asyncio
    async def test_execute_aws_command_sandbox_error(self):
        from aws_mcp_server.sandbox import SandboxError

        with patch(
            "aws_mcp_server.cli_executor.execute_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.side_effect = SandboxError("sandbox violation")

            with pytest.raises(CommandExecutionError) as excinfo:
                await execute_aws_command("aws s3 ls")

            assert "Sandbox execution error" in str(excinfo.value)
            assert "blocked by the OS-level sandbox" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_execute_pipe_command_sandbox_error(self):
        from aws_mcp_server.sandbox import SandboxError

        with patch(
            "aws_mcp_server.cli_executor.execute_piped_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.side_effect = SandboxError("sandbox violation")

            with pytest.raises(CommandExecutionError) as excinfo:
                await execute_pipe_command("aws s3 ls | grep bucket")

            assert "Sandbox execution error" in str(excinfo.value)
            assert "piped command was blocked" in str(excinfo.value)


class TestCancelledErrorHandling:
    @pytest.mark.asyncio
    async def test_execute_aws_command_cancelled_error(self):
        with patch(
            "aws_mcp_server.cli_executor.execute_sandboxed_async",
            new_callable=AsyncMock,
        ) as mock_sandbox:
            mock_sandbox.side_effect = asyncio.CancelledError()

            with pytest.raises(asyncio.CancelledError):
                await execute_aws_command("aws s3 ls")
