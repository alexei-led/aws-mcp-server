"""Mocked integration tests for AWS MCP Server functionality.

These tests use mocks rather than actual AWS CLI calls, so they can
run without AWS credentials or AWS CLI installed.
"""

import json
import logging
import os
from unittest.mock import patch

import pytest

from aws_mcp_server.server import describe_command, execute_command, mcp

# Enable debug logging for tests
logging.basicConfig(level=logging.DEBUG)


@pytest.fixture
def mock_aws_environment():
    """Set up mock AWS environment variables for testing."""
    original_env = os.environ.copy()
    os.environ["AWS_PROFILE"] = "test-profile"
    os.environ["AWS_REGION"] = "us-west-2"
    yield
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mcp_client():
    """Return a FastMCP client for testing."""
    return mcp


class TestServerIntegration:
    """Integration tests for the AWS MCP Server using mocks.

    These tests use mocks and don't actually call AWS, but they test
    more of the system together than unit tests. They don't require the
    integration marker since they can run without AWS CLI or credentials."""

    @pytest.mark.asyncio
    @patch("aws_mcp_server.utils.cli_executor.execute_aws_command")
    async def test_describe_command_integration(self, mock_execute, mock_aws_environment):
        """Test the describe_command functionality end-to-end."""
        # Mock the AWS CLI response
        mock_execute.return_value = {"status": "success", "output": "AWS S3 HELP\nCommands:\ncp\nls\nmv\nrm\nsync"}

        # Call the describe_command function
        result = await describe_command("s3")

        # Verify the results
        assert "help_text" in result
        assert "AWS S3 HELP" in result["help_text"]
        assert "Commands" in result["help_text"]

        # Verify the mock was called correctly
        mock_execute.assert_called_once()
        call_args = mock_execute.call_args[0][0]
        assert "aws s3 help" == call_args

    @pytest.mark.asyncio
    @patch("aws_mcp_server.utils.cli_executor.execute_aws_command")
    async def test_execute_command_with_json_output(self, mock_execute, mock_aws_environment):
        """Test the execute_command with JSON output formatting."""
        # Mock the JSON response from AWS CLI
        json_response = json.dumps({"Buckets": [{"Name": "test-bucket", "CreationDate": "2023-01-01T00:00:00Z"}]})
        mock_execute.return_value = {"status": "success", "output": json_response}

        # Call the execute_command function
        result = await execute_command("aws s3 ls --output json")

        # Verify the results
        assert result["status"] == "success"
        assert "Buckets" in result["output"]
        assert "test-bucket" in result["output"]

        # Verify the mock was called correctly
        mock_execute.assert_called_once_with("aws s3 ls --output json")

    @pytest.mark.asyncio
    @patch("aws_mcp_server.utils.cli_executor.execute_aws_command")
    async def test_execute_command_error_handling(self, mock_execute, mock_aws_environment):
        """Test error handling in execute_command."""
        # Mock an error response from AWS CLI
        mock_execute.return_value = {"status": "error", "output": "An error occurred: access denied"}

        # Call the execute_command function
        result = await execute_command("aws s3 ls --invalid-flag")

        # Verify the results
        assert result["status"] == "error"
        assert "An error occurred" in result["output"]
