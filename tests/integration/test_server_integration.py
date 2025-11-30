"""Mocked integration tests for AWS MCP Server functionality."""

import json
import logging
import os
from unittest.mock import patch

import pytest

from aws_mcp_server.server import aws_cli_help, aws_cli_pipeline, mcp

logging.basicConfig(level=logging.DEBUG)


@pytest.fixture
def mock_aws_environment():
    """Set up mock AWS environment variables for testing."""
    original_env = os.environ.copy()
    os.environ["AWS_PROFILE"] = "test-profile"
    os.environ["AWS_REGION"] = "us-west-2"
    yield
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mcp_client():
    """Return a FastMCP client for testing."""
    return mcp


class TestServerIntegration:
    """Integration tests for the AWS MCP Server using mocks."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "service,command,mock_response,expected_content",
        [
            (
                "s3",
                None,
                {"help_text": "AWS S3 HELP\nCommands:\ncp\nls\nmv\nrm\nsync"},
                ["AWS S3 HELP", "Commands", "ls", "sync"],
            ),
            (
                "ec2",
                "describe-instances",
                {"help_text": "DESCRIPTION\n  Describes the specified instances.\n\nSYNOPSIS\n  describe-instances\n  [--instance-ids <value>]"},
                ["DESCRIPTION", "SYNOPSIS", "instance-ids"],
            ),
            (
                "lambda",
                "list-functions",
                {"help_text": "LAMBDA LIST-FUNCTIONS\nLists your Lambda functions"},
                ["LAMBDA", "LIST-FUNCTIONS", "Lists"],
            ),
        ],
    )
    @patch("aws_mcp_server.server.get_command_help")
    async def test_aws_cli_help_integration(
        self,
        mock_get_help,
        mock_aws_environment,
        service,
        command,
        mock_response,
        expected_content,
    ):
        """Test the aws_cli_help functionality with table-driven tests."""
        mock_get_help.return_value = mock_response

        result = await aws_cli_help(service=service, command=command, ctx=None)

        assert "help_text" in result
        for content in expected_content:
            assert content in result["help_text"], f"Expected '{content}' in help text"

        mock_get_help.assert_called_once_with(service, command)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "command,mock_response,expected_result,timeout",
        [
            (
                "aws s3 ls --output json",
                {
                    "status": "success",
                    "output": json.dumps(
                        {
                            "Buckets": [
                                {
                                    "Name": "test-bucket",
                                    "CreationDate": "2023-01-01T00:00:00Z",
                                }
                            ]
                        }
                    ),
                },
                {"status": "success", "contains": ["Buckets", "test-bucket"]},
                None,
            ),
            (
                "aws ec2 describe-instances --query 'Reservations[*]' --output text",
                {"status": "success", "output": "i-12345\trunning\tt2.micro"},
                {"status": "success", "contains": ["i-12345", "running"]},
                None,
            ),
            (
                "aws rds describe-db-instances",
                {"status": "success", "output": "DB instances list"},
                {"status": "success", "contains": ["DB instances"]},
                60,
            ),
            (
                "aws s3 ls --invalid-flag",
                {"status": "error", "output": "Unknown options: --invalid-flag"},
                {"status": "error", "contains": ["--invalid-flag"]},
                None,
            ),
            (
                "aws s3api list-buckets --query 'Buckets[*].Name' --output text | sort",
                {"status": "success", "output": "bucket1\nbucket2\nbucket3"},
                {"status": "success", "contains": ["bucket1", "bucket3"]},
                None,
            ),
        ],
    )
    @patch("aws_mcp_server.server.execute_aws_command")
    async def test_aws_cli_pipeline_scenarios(
        self,
        mock_execute,
        mock_aws_environment,
        command,
        mock_response,
        expected_result,
        timeout,
    ):
        """Test aws_cli_pipeline with various scenarios using table-driven tests."""
        mock_execute.return_value = mock_response

        result = await aws_cli_pipeline(command=command, timeout=timeout, ctx=None)

        assert result["status"] == expected_result["status"]

        for content in expected_result["contains"]:
            assert content in result["output"], f"Expected '{content}' in output"

        mock_execute.assert_called_once_with(command, timeout)

    @pytest.mark.asyncio
    @patch("aws_mcp_server.resources.get_aws_profiles")
    @patch("aws_mcp_server.resources.get_aws_regions")
    @patch("aws_mcp_server.resources.get_aws_environment")
    @patch("aws_mcp_server.resources.get_aws_account_info")
    async def test_mcp_resources_access(
        self,
        mock_get_aws_account_info,
        mock_get_aws_environment,
        mock_get_aws_regions,
        mock_get_aws_profiles,
        mock_aws_environment,
        mcp_client,
    ):
        """Test that MCP resources are properly registered and accessible to clients."""
        mock_get_aws_profiles.return_value = ["default", "test-profile", "dev"]
        mock_get_aws_regions.return_value = [
            {"RegionName": "us-east-1", "RegionDescription": "US East (N. Virginia)"},
            {"RegionName": "us-west-2", "RegionDescription": "US West (Oregon)"},
        ]
        mock_get_aws_environment.return_value = {
            "aws_profile": "test-profile",
            "aws_region": "us-west-2",
            "has_credentials": True,
            "credentials_source": "profile",
        }
        mock_get_aws_account_info.return_value = {
            "account_id": "123456789012",
            "account_alias": "test-account",
            "organization_id": "o-abcdef123456",
        }

        expected_resources = [
            "aws://config/profiles",
            "aws://config/regions",
            "aws://config/environment",
            "aws://config/account",
        ]

        resources = await mcp_client.list_resources()

        resource_uris = [str(r.uri) for r in resources]
        for uri in expected_resources:
            assert uri in resource_uris, f"Resource {uri} not found in resources list"

        for uri in expected_resources:
            resource = await mcp_client.read_resource(uri=uri)
            assert resource is not None, f"Failed to read resource {uri}"

            import json

            content = json.loads(resource[0].content)

            if uri == "aws://config/profiles":
                assert "profiles" in content
                assert len(content["profiles"]) == 3
                assert any(p["name"] == "test-profile" and p["is_current"] for p in content["profiles"])

            elif uri == "aws://config/regions":
                assert "regions" in content
                assert len(content["regions"]) == 2
                assert any(r["name"] == "us-west-2" and r["is_current"] for r in content["regions"])

            elif uri == "aws://config/environment":
                assert content["aws_profile"] == "test-profile"
                assert content["aws_region"] == "us-west-2"
                assert content["has_credentials"] is True

            elif uri == "aws://config/account":
                assert content["account_id"] == "123456789012"
                assert content["account_alias"] == "test-account"
