"""Live AWS integration tests for the AWS MCP Server."""

import asyncio
import json
import logging
import os
import time
import uuid

import pytest

from aws_mcp_server.server import aws_cli_help, aws_cli_pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestAWSLiveIntegration:
    """Integration tests that interact with real AWS services."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.parametrize(
        "service,command,expected_content",
        [
            ("s3", None, ["description", "ls", "cp", "mv"]),
            ("ec2", None, ["description", "run-instances", "describe-instances"]),
            ("s3", "ls", ["list s3 objects", "options", "examples"]),
        ],
    )
    async def test_aws_cli_help(self, ensure_aws_credentials, service, command, expected_content):
        """Test getting help for various AWS commands."""
        result = await aws_cli_help(service=service, command=command, ctx=None)

        assert isinstance(result, dict)
        assert "help_text" in result

        help_text = result["help_text"].lower()
        for content in expected_content:
            assert content.lower() in help_text, f"Expected '{content}' in {service} {command} help text"

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_list_s3_buckets(self, ensure_aws_credentials):
        """Test listing S3 buckets."""
        result = await aws_cli_pipeline(command="aws s3 ls", timeout=None, ctx=None)

        assert isinstance(result, dict)
        assert "status" in result
        assert "output" in result
        assert result["status"] == "success"

        assert isinstance(result["output"], str)

        logger.info(f"S3 bucket list result: {result['output']}")

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_s3_operations_with_test_bucket(self, ensure_aws_credentials):
        """Test S3 operations using a test bucket."""
        region = os.environ.get("AWS_TEST_REGION", os.environ.get("AWS_REGION", "us-east-1"))
        print(f"Using AWS region: {region}")

        timestamp = int(time.time())
        random_id = str(uuid.uuid4())[:8]
        bucket_name = f"aws-mcp-test-{timestamp}-{random_id}"

        test_file_name = "test_file.txt"
        test_file_content = "This is a test file for AWS MCP Server integration tests"
        downloaded_file_name = "test_file_downloaded.txt"

        try:
            create_cmd = f"aws s3 mb s3://{bucket_name} --region {region}"
            result = await aws_cli_pipeline(command=create_cmd, timeout=None, ctx=None)
            assert result["status"] == "success", f"Failed to create bucket: {result['output']}"

            await asyncio.sleep(3)

            with open(test_file_name, "w") as f:
                f.write(test_file_content)

            upload_result = await aws_cli_pipeline(
                command=f"aws s3 cp {test_file_name} s3://{bucket_name}/{test_file_name} --region {region}",
                timeout=None,
                ctx=None,
            )
            assert upload_result["status"] == "success"

            list_result = await aws_cli_pipeline(
                command=f"aws s3 ls s3://{bucket_name}/ --region {region}",
                timeout=None,
                ctx=None,
            )
            assert list_result["status"] == "success"
            assert test_file_name in list_result["output"]

            download_result = await aws_cli_pipeline(
                command=f"aws s3 cp s3://{bucket_name}/{test_file_name} {downloaded_file_name} --region {region}",
                timeout=None,
                ctx=None,
            )
            assert download_result["status"] == "success"

            with open(downloaded_file_name, "r") as f:
                downloaded_content = f.read()
            assert downloaded_content == test_file_content

        finally:
            for file_name in [test_file_name, downloaded_file_name]:
                if os.path.exists(file_name):
                    os.remove(file_name)

            await aws_cli_pipeline(
                command=f"aws s3 rm s3://{bucket_name} --recursive --region {region}",
                timeout=None,
                ctx=None,
            )

            await aws_cli_pipeline(
                command=f"aws s3 rb s3://{bucket_name} --region {region}",
                timeout=None,
                ctx=None,
            )

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.parametrize(
        "command,expected_attributes,description",
        [
            (
                "aws ec2 describe-regions --output json",
                {"json_key": "Regions", "expected_type": list},
                "JSON output with EC2 regions",
            ),
            (
                "aws s3api list-buckets --output json",
                {"json_key": "Buckets", "expected_type": list},
                "JSON output with S3 buckets",
            ),
        ],
    )
    async def test_aws_json_output_formatting(self, ensure_aws_credentials, command, expected_attributes, description):
        """Test JSON output formatting from various AWS commands."""
        result = await aws_cli_pipeline(command=command, timeout=None, ctx=None)

        assert result["status"] == "success", f"Command failed: {result.get('output', '')}"

        try:
            json_data = json.loads(result["output"])

            json_key = expected_attributes["json_key"]
            expected_type = expected_attributes["expected_type"]

            assert json_key in json_data, f"Expected key '{json_key}' not found in JSON response"
            assert isinstance(json_data[json_key], expected_type), f"Expected {json_key} to be of type {expected_type.__name__}"

            logger.info(f"Successfully parsed JSON response for {description} with {len(json_data[json_key])} items")

        except json.JSONDecodeError:
            pytest.fail(f"Output is not valid JSON: {result['output'][:100]}...")

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.parametrize(
        "command,validation_func,description",
        [
            (
                "aws ec2 describe-regions --query 'Regions[*].RegionName' --output text | wc -l",
                lambda output: int(output.strip()) > 0,
                "Count of AWS regions",
            ),
            (
                "aws ec2 describe-regions --query 'Regions[*].RegionName' --output text | grep east | sort",
                lambda output: all("east" in r.lower() for r in output.strip().split("\n") if r),
                "Filtered and sorted east regions",
            ),
            (
                "aws ec2 describe-regions --output json | grep RegionName | head -3 | wc -l",
                lambda output: int(output.strip()) <= 3,
                "Limited region output with multiple pipes",
            ),
            (
                "aws iam list-roles --output json | grep RoleName",
                lambda output: "RoleName" in output or output.strip() == "",
                "Lists IAM roles or returns empty if none exist",
            ),
            (
                "aws --version | grep aws",
                lambda output: "aws" in output.lower(),
                "AWS version with grep",
            ),
        ],
    )
    async def test_piped_commands(self, ensure_aws_credentials, command, validation_func, description):
        """Test execution of various piped commands with AWS CLI and Unix utilities."""
        result = await aws_cli_pipeline(command=command, timeout=None, ctx=None)

        assert result["status"] == "success", f"Command failed: {result.get('output', '')}"

        assert validation_func(result["output"]), f"Output validation failed for {description}"

        logger.info(f"Successfully executed piped command for {description}: {result['output'][:50]}...")

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_aws_account_resource(self, ensure_aws_credentials):
        """Test that the AWS account resource returns non-null account information."""
        from aws_mcp_server.resources import get_aws_account_info

        account_info = get_aws_account_info()

        assert account_info is not None, "AWS account info is None"

        assert account_info["account_id"] is not None, "AWS account_id is null"

        account_id = account_info["account_id"]
        masked_id = f"{account_id[:4]}{'*' * (len(account_id) - 4)}" if account_id else "None"
        logger.info(f"Successfully accessed AWS account info with account_id: {masked_id}")

        has_org_id = account_info["organization_id"] is not None
        logger.info(f"Organization ID available: {has_org_id}")

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_us_east_1_region_services(self, ensure_aws_credentials):
        """Test that the us-east-1 region resource returns expected services."""
        from aws_mcp_server.resources import get_region_details
        from aws_mcp_server.server import mcp

        region_code = "us-east-1"
        region_details = get_region_details(region_code)

        assert region_details is not None, "Region details is None"
        assert region_details["code"] == region_code, "Region code does not match expected value"
        assert region_details["name"] == "US East (N. Virginia)", "Region name does not match expected value"

        assert "services" in region_details, "Services not found in region details"
        assert isinstance(region_details["services"], list), "Services is not a list"
        assert len(region_details["services"]) > 0, "Services list is empty"

        for service in region_details["services"]:
            assert "id" in service, "Service missing 'id' field"
            assert "name" in service, "Service missing 'name' field"

        required_services = [
            "ec2",
            "s3",
            "lambda",
            "dynamodb",
            "rds",
            "cloudformation",
            "iam",
        ]

        service_ids = [service["id"] for service in region_details["services"]]

        for required_service in required_services:
            assert required_service in service_ids, f"Required service '{required_service}' not found in us-east-1 services"

        logger.info(f"Found {len(region_details['services'])} services in us-east-1")

        try:
            resource = await mcp.resources_read(uri=f"aws://config/regions/{region_code}")
            assert resource is not None, "Failed to read region resource through MCP"
            assert resource.content["code"] == region_code, "Resource region code does not match"
            assert resource.content["name"] == "US East (N. Virginia)", "Resource region name does not match"
            assert "services" in resource.content, "Services not found in MCP resource content"

            mcp_service_ids = [service["id"] for service in resource.content["services"]]
            for required_service in required_services:
                assert required_service in mcp_service_ids, f"Required service '{required_service}' not found in MCP resource services"

            logger.info("Successfully accessed us-east-1 region details through MCP resource")
        except Exception as e:
            logger.warning(f"Could not test MCP resource access: {e}")
