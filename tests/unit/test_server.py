"""Tests for the FastMCP server implementation."""

from unittest.mock import ANY, AsyncMock, patch

import pytest

from aws_mcp_server.cli_executor import CommandExecutionError
from aws_mcp_server.server import (
    SERVER_DESCRIPTION,
    aws_cli_help,
    aws_cli_pipeline,
    mcp,
    run_startup_checks,
)


def test_run_startup_checks():
    with patch("aws_mcp_server.server.check_aws_cli_installed") as mock_check:
        mock_check.return_value = None

        with patch("aws_mcp_server.server.asyncio.run", return_value=True):
            with patch("sys.exit") as mock_exit:
                run_startup_checks()
                mock_exit.assert_not_called()

    with patch("aws_mcp_server.server.check_aws_cli_installed") as mock_check:
        mock_check.return_value = None

        with patch("aws_mcp_server.server.asyncio.run", return_value=False):
            with patch("sys.exit") as mock_exit:
                run_startup_checks()
                mock_exit.assert_called_once_with(1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "service,command,expected_result",
    [
        ("s3", None, {"help_text": "Test help text"}),
        ("s3", "ls", {"help_text": "Test help text"}),
        ("ec2", "describe-instances", {"help_text": "Test help text"}),
    ],
)
async def test_aws_cli_help(service, command, expected_result):
    with patch("aws_mcp_server.server.get_command_help", new_callable=AsyncMock) as mock_get_help:
        mock_get_help.return_value = expected_result

        result = await aws_cli_help(service=service, command=command)

        assert result == expected_result

        mock_get_help.assert_called_with(service, command)


@pytest.mark.asyncio
async def test_aws_cli_help_with_context():
    mock_ctx = AsyncMock()

    with patch("aws_mcp_server.server.get_command_help", new_callable=AsyncMock) as mock_get_help:
        mock_get_help.return_value = {"help_text": "Test help text"}

        result = await aws_cli_help(service="s3", command="ls", ctx=mock_ctx)

        assert result == {"help_text": "Test help text"}
        mock_ctx.info.assert_called_once()
        assert "Fetching help for AWS s3 ls" in mock_ctx.info.call_args[0][0]


@pytest.mark.asyncio
async def test_aws_cli_help_exception_handling():
    with patch(
        "aws_mcp_server.server.get_command_help",
        side_effect=Exception("Test exception"),
    ):
        result = await aws_cli_help(service="s3")

        assert "help_text" in result
        assert "Error retrieving help" in result["help_text"]
        assert "Test exception" in result["help_text"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command,timeout,expected_result",
    [
        ("aws s3 ls", None, {"status": "success", "output": "Test output"}),
        ("aws s3 ls", 60, {"status": "success", "output": "Test output"}),
        (
            "aws ec2 describe-instances --filters Name=instance-state-name,Values=running",
            None,
            {"status": "success", "output": "Running instances"},
        ),
    ],
)
async def test_aws_cli_pipeline_success(command, timeout, expected_result):
    with patch("aws_mcp_server.server.check_aws_cli_installed", return_value=None):
        with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = expected_result

            result = await aws_cli_pipeline(command=command, timeout=timeout)

            assert result["status"] == expected_result["status"]
            assert result["output"] == expected_result["output"]

            mock_execute.assert_called_with(command, timeout if timeout else ANY)


@pytest.mark.asyncio
async def test_aws_cli_pipeline_with_context():
    mock_ctx = AsyncMock()

    with patch("aws_mcp_server.server.check_aws_cli_installed", return_value=None):
        with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = {"status": "success", "output": "Test output"}

            result = await aws_cli_pipeline(command="aws s3 ls", ctx=mock_ctx)

            assert result["status"] == "success"
            assert result["output"] == "Test output"

            assert mock_ctx.info.call_count == 2
            assert "Executing" in mock_ctx.info.call_args_list[0][0][0]
            assert "Command executed successfully" in mock_ctx.info.call_args_list[1][0][0]

        mock_ctx.reset_mock()
        with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = {"status": "error", "output": "Error output"}

            result = await aws_cli_pipeline(command="aws s3 ls", ctx=mock_ctx)

            assert result["status"] == "error"
            assert result["output"] == "Error output"

            assert mock_ctx.info.call_count == 1
            assert mock_ctx.warning.call_count == 1
            assert "Command failed" in mock_ctx.warning.call_args[0][0]


@pytest.mark.asyncio
async def test_aws_cli_pipeline_with_context_and_timeout():
    mock_ctx = AsyncMock()

    with patch("aws_mcp_server.server.check_aws_cli_installed", return_value=None):
        with patch("aws_mcp_server.server.execute_aws_command", new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = {"status": "success", "output": "Test output"}

            await aws_cli_pipeline(command="aws s3 ls", timeout=60, ctx=mock_ctx)

            message = mock_ctx.info.call_args_list[0][0][0]
            assert "with timeout: 60s" in message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command,exception,expected_error_type,expected_message",
    [
        (
            "aws s3 ls",
            CommandExecutionError("Execution failed"),
            "Command execution error",
            "Execution failed",
        ),
        (
            "aws ec2 describe-instances",
            CommandExecutionError("Command timed out"),
            "Command execution error",
            "Command timed out",
        ),
        (
            "aws dynamodb scan",
            Exception("Unexpected error"),
            "Unexpected error",
            "Unexpected error",
        ),
    ],
)
async def test_aws_cli_pipeline_errors(command, exception, expected_error_type, expected_message):
    with patch("aws_mcp_server.server.check_aws_cli_installed", return_value=None):
        with patch("aws_mcp_server.server.execute_aws_command", side_effect=exception) as mock_execute:
            result = await aws_cli_pipeline(command=command)

            assert result["status"] == "error"
            assert expected_error_type in result["output"]
            assert expected_message in result["output"]

            mock_execute.assert_called_with(command, ANY)


@pytest.mark.asyncio
async def test_mcp_server_initialization():
    assert mcp.name == "AWS MCP Server"

    assert callable(aws_cli_help)
    assert callable(aws_cli_pipeline)


def test_mcp_server_has_description():
    assert SERVER_DESCRIPTION
    assert "MCP server" in SERVER_DESCRIPTION
    assert "AWS CLI" in SERVER_DESCRIPTION
    assert SERVER_DESCRIPTION in mcp._mcp_server.instructions
