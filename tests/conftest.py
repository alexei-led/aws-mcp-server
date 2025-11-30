"""Configuration for pytest."""

import os

import pytest


def pytest_addoption(parser):
    """Add command-line options to pytest."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests that require AWS CLI and AWS account",
    )


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: mark test as requiring AWS CLI and AWS account")


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --run-integration is specified."""
    if config.getoption("--run-integration"):
        return

    skip_integration = pytest.mark.skip(reason="Integration tests need --run-integration option")

    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture(scope="function")
async def aws_s3_bucket(ensure_aws_credentials):
    """Create or use an S3 bucket for integration tests.

    Uses AWS_TEST_BUCKET if specified, otherwise creates a temporary bucket
    and cleans it up after tests complete.
    """
    import asyncio
    import time
    import uuid

    from aws_mcp_server.server import aws_cli_pipeline

    bucket_name = os.environ.get("AWS_TEST_BUCKET")
    bucket_created = False
    region = os.environ.get("AWS_TEST_REGION", os.environ.get("AWS_REGION", "us-east-1"))

    if not bucket_name:
        timestamp = int(time.time())
        random_id = str(uuid.uuid4())[:8]
        bucket_name = f"aws-mcp-test-{timestamp}-{random_id}"

        create_cmd = f"aws s3 mb s3://{bucket_name} --region {region}"
        result = await aws_cli_pipeline(command=create_cmd, timeout=None, ctx=None)
        if result["status"] != "success":
            pytest.skip(f"Failed to create test bucket: {result['output']}")
        bucket_created = True
        await asyncio.sleep(3)

    yield bucket_name

    if bucket_created:
        try:
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
        except Exception:
            pass


@pytest.fixture
def ensure_aws_credentials():
    """Ensure AWS credentials are configured and AWS CLI is installed."""
    import subprocess

    try:
        result = subprocess.run(
            ["aws", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("AWS CLI not installed or not in PATH")
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("AWS CLI not installed or not in PATH")

    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            error_msg = result.stderr.decode("utf-8")
            pytest.skip(f"AWS credentials not valid: {error_msg}")
    except subprocess.SubprocessError:
        pytest.skip("Failed to verify AWS credentials")

    return True
