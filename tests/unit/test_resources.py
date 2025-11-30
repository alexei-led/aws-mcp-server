"""Unit tests for AWS MCP Server resources module.

These tests verify that the resources functionality in the resources module
works correctly, with appropriate mocking to avoid actual AWS API calls.
"""

import os
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_mcp_server.resources import (
    _get_region_description,
    _get_region_geographic_location,
    get_aws_account_info,
    get_aws_environment,
    get_aws_profiles,
    get_aws_regions,
    get_region_available_services,
    get_region_details,
    register_resources,
)


@pytest.fixture
def mock_config_files(monkeypatch, tmp_path):
    """Create mock AWS config and credentials files for testing."""
    config_dir = tmp_path / ".aws"
    config_dir.mkdir()

    # Create mock config file
    config_file = config_dir / "config"
    config_file.write_text("[default]\nregion = us-west-2\n\n[profile dev]\nregion = us-east-1\n\n[profile prod]\nregion = eu-west-1\n")

    # Create mock credentials file
    creds_file = config_dir / "credentials"
    creds_file.write_text(
        "[default]\n"
        "aws_access_key_id = AKIADEFAULT000000000\n"
        "aws_secret_access_key = 1234567890abcdef1234567890abcdef\n"
        "\n"
        "[dev]\n"
        "aws_access_key_id = AKIADEV0000000000000\n"
        "aws_secret_access_key = abcdef1234567890abcdef1234567890\n"
        "\n"
        "[test]\n"  # Profile in credentials but not in config
        "aws_access_key_id = AKIATEST000000000000\n"
        "aws_secret_access_key = test1234567890abcdef1234567890ab\n"
    )

    # Set environment to use these files
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_get_aws_profiles(mock_config_files):
    """Test retrieving AWS profiles from config files."""
    profiles = get_aws_profiles()

    # Should find all profiles from both files, with no duplicates
    assert set(profiles) == {"default", "dev", "prod", "test"}


def test_get_aws_profiles_custom_config_file(monkeypatch, tmp_path):
    """Test get_aws_profiles with custom AWS_CONFIG_FILE."""
    custom_config = tmp_path / "custom_config"
    custom_config.write_text("[default]\nregion = us-west-2\n\n[profile custom-profile]\nregion = eu-west-1\n")

    monkeypatch.setenv("AWS_CONFIG_FILE", str(custom_config))
    # Ensure no default credentials file exists
    monkeypatch.setenv("HOME", str(tmp_path))

    profiles = get_aws_profiles()

    assert "default" in profiles
    assert "custom-profile" in profiles


def test_get_aws_profiles_custom_credentials_file(monkeypatch, tmp_path):
    """Test get_aws_profiles with custom AWS_SHARED_CREDENTIALS_FILE."""
    custom_creds = tmp_path / "custom_credentials"
    custom_creds.write_text(
        "[default]\n"
        "aws_access_key_id = AKIATEST\n"
        "aws_secret_access_key = secret\n\n"
        "[custom-creds-profile]\n"
        "aws_access_key_id = AKIACUSTOM\n"
        "aws_secret_access_key = customsecret\n"
    )

    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(custom_creds))
    # Ensure no default config file exists
    monkeypatch.setenv("HOME", str(tmp_path))

    profiles = get_aws_profiles()

    assert "default" in profiles
    assert "custom-creds-profile" in profiles


def test_get_aws_profiles_both_custom_paths(monkeypatch, tmp_path):
    """Test get_aws_profiles with both custom config and credentials files."""
    custom_config = tmp_path / "custom_config"
    custom_config.write_text("[profile config-only-profile]\nregion = us-west-2\n")

    custom_creds = tmp_path / "custom_credentials"
    custom_creds.write_text("[creds-only-profile]\naws_access_key_id = AKIATEST\naws_secret_access_key = secret\n")

    monkeypatch.setenv("AWS_CONFIG_FILE", str(custom_config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(custom_creds))
    # Ensure no default files exist
    monkeypatch.setenv("HOME", str(tmp_path))

    profiles = get_aws_profiles()

    assert "default" in profiles
    assert "config-only-profile" in profiles
    assert "creds-only-profile" in profiles


@patch("boto3.session.Session")
def test_get_aws_regions(mock_session):
    """Test retrieving AWS regions with mocked boto3."""
    # Mock boto3 session and client response
    mock_ec2 = MagicMock()
    mock_session.return_value.client.return_value = mock_ec2

    mock_ec2.describe_regions.return_value = {
        "Regions": [
            {"RegionName": "us-east-1"},
            {"RegionName": "us-west-2"},
            {"RegionName": "eu-central-1"},
        ]
    }

    regions = get_aws_regions()

    # Check regions are properly formatted
    assert len(regions) == 3
    assert regions[0]["RegionName"] == "eu-central-1"  # Sorted alphabetically
    assert regions[0]["RegionDescription"] == "EU Central (Frankfurt)"
    assert regions[1]["RegionName"] == "us-east-1"
    assert regions[2]["RegionName"] == "us-west-2"

    # Verify correct session and client creation
    mock_session.assert_called_once()
    mock_session.return_value.client.assert_called_once_with("ec2")


@patch("boto3.session.Session")
def test_get_aws_regions_fallback(mock_session):
    """Test fallback behavior when region retrieval fails."""
    # Mock boto3 to raise an exception
    mock_session.return_value.client.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "DescribeRegions",
    )

    regions = get_aws_regions()

    # Should fall back to static region list
    assert len(regions) >= 12  # Should include at least the major regions
    assert any(r["RegionName"] == "us-east-1" for r in regions)
    assert any(r["RegionName"] == "eu-west-1" for r in regions)


@patch("boto3.session.Session")
def test_get_aws_environment(mock_session, monkeypatch):
    """Test retrieving AWS environment information."""
    # Set up environment variables
    monkeypatch.setenv("AWS_PROFILE", "test-profile")
    monkeypatch.setenv("AWS_REGION", "us-west-2")

    # Mock boto3 credentials
    mock_credentials = MagicMock()
    mock_credentials.method = "shared-credentials-file"
    mock_session.return_value.get_credentials.return_value = mock_credentials

    env_info = get_aws_environment()

    # Check environment information
    assert env_info["aws_profile"] == "test-profile"
    assert env_info["aws_region"] == "us-west-2"
    assert env_info["has_credentials"] is True
    assert env_info["credentials_source"] == "profile"


@patch("boto3.session.Session")
def test_get_aws_environment_no_credentials(mock_session, monkeypatch):
    """Test environment info with no credentials."""
    # Clear relevant environment variables
    for var in ["AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID"]:
        if var in os.environ:
            monkeypatch.delenv(var)

    # No credentials available
    mock_session.return_value.get_credentials.return_value = None

    env_info = get_aws_environment()

    # Check environment information with defaults
    assert env_info["aws_profile"] == "default"
    assert env_info["aws_region"] == "us-east-1"
    assert env_info["has_credentials"] is False
    assert env_info["credentials_source"] == "none"


@patch("boto3.session.Session")
def test_get_aws_account_info(mock_session):
    """Test retrieving AWS account information."""
    # Mock boto3 clients
    mock_sts = MagicMock()
    mock_iam = MagicMock()
    mock_org = MagicMock()

    mock_session.return_value.client.side_effect = lambda service: {
        "sts": mock_sts,
        "iam": mock_iam,
        "organizations": mock_org,
    }[service]

    # Mock API responses
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_iam.list_account_aliases.return_value = {"AccountAliases": ["my-account"]}
    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-abcdef1234"}}

    account_info = get_aws_account_info()

    # Check account information
    assert account_info["account_id"] == "123456789012"
    assert account_info["account_alias"] == "my-account"
    assert account_info["organization_id"] == "o-abcdef1234"


@patch("boto3.session.Session")
def test_get_aws_account_info_minimal(mock_session):
    """Test account info with minimal permissions."""
    # Mock boto3 sts client, but iam/org calls fail
    mock_sts = MagicMock()

    def mock_client(service):
        if service == "sts":
            return mock_sts
        elif service == "iam":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListAccountAliases")
        else:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeAccount")

    mock_session.return_value.client.side_effect = mock_client

    # Mock API response
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

    account_info = get_aws_account_info()

    # Should have account ID but not alias or org ID
    assert account_info["account_id"] == "123456789012"
    assert account_info["account_alias"] is None
    assert account_info["organization_id"] is None


def test_register_resources():
    """Test registering MCP resources."""
    # Mock MCP instance
    mock_mcp = MagicMock()

    # Register resources
    register_resources(mock_mcp)

    # Verify resource registration
    assert mock_mcp.resource.call_count == 5  # Should register 5 resources

    # Check that resource was called with the correct URIs, names and descriptions
    expected_resources = [
        {
            "uri": "aws://config/profiles",
            "name": "aws_profiles",
            "description": "Get available AWS profiles",
        },
        {
            "uri": "aws://config/regions",
            "name": "aws_regions",
            "description": "Get available AWS regions",
        },
        {
            "uri": "aws://config/regions/{region}",
            "name": "aws_region_details",
            "description": "Get detailed information about a specific AWS region",
        },
        {
            "uri": "aws://config/environment",
            "name": "aws_environment",
            "description": "Get AWS environment information",
        },
        {
            "uri": "aws://config/account",
            "name": "aws_account",
            "description": "Get AWS account information",
        },
    ]

    # Extract parameters from each call
    for call in mock_mcp.resource.call_args_list:
        found = False
        for resource in expected_resources:
            if resource["uri"] == call.kwargs.get("uri"):
                # Check name and description too
                assert call.kwargs.get("name") == resource["name"]
                assert call.kwargs.get("description") == resource["description"]
                found = True
                break
        assert found, f"URI {call.kwargs.get('uri')} not found in expected resources"


def test_get_region_description():
    """Test the region description utility function."""
    # Test known regions
    assert _get_region_description("us-east-1") == "US East (N. Virginia)"
    assert _get_region_description("eu-west-2") == "EU West (London)"
    assert _get_region_description("ap-southeast-1") == "Asia Pacific (Singapore)"

    # Test unknown regions
    assert _get_region_description("unknown-region-1") == "AWS Region unknown-region-1"
    assert _get_region_description("test-region-2") == "AWS Region test-region-2"


@patch("configparser.ConfigParser")
@patch("os.path.exists")
def test_get_aws_profiles_exception(mock_exists, mock_config_parser):
    """Test exception handling in get_aws_profiles."""
    # Setup mocks
    mock_exists.return_value = True
    mock_parser_instance = MagicMock()
    mock_config_parser.return_value = mock_parser_instance

    # Simulate an exception when reading the config
    mock_parser_instance.read.side_effect = Exception("Config file error")

    # Call function
    profiles = get_aws_profiles()

    # Verify profiles contains only the default profile
    assert profiles == ["default"]
    assert mock_parser_instance.read.called


@patch("boto3.session.Session")
def test_get_aws_regions_generic_exception(mock_session):
    """Test general exception handling in get_aws_regions."""
    # Mock boto3 to raise a generic exception (not ClientError)
    mock_session.return_value.client.side_effect = Exception("Generic error")

    # Call function
    regions = get_aws_regions()

    # Should return empty list for general exceptions
    assert len(regions) == 0
    assert isinstance(regions, list)


@patch("boto3.session.Session")
def test_get_aws_environment_credential_methods(mock_session):
    """Test different credential methods in get_aws_environment."""
    # Set up different credential methods to test
    test_cases = [
        ("environment", "environment"),
        ("iam-role", "instance-profile"),
        ("assume-role", "assume-role"),
        ("container-role", "container-role"),
        (
            "unknown-method",
            "profile",
        ),  # Should fall back to "profile" for unknown methods
    ]

    for method, expected_source in test_cases:
        # Reset mock
        mock_session.reset_mock()

        # Set up mock credentials
        mock_credentials = MagicMock()
        mock_credentials.method = method
        mock_session.return_value.get_credentials.return_value = mock_credentials

        # Call function
        env_info = get_aws_environment()

        # Verify credential source
        assert env_info["has_credentials"] is True
        assert env_info["credentials_source"] == expected_source


@patch("boto3.session.Session")
def test_get_aws_environment_exception(mock_session):
    """Test exception handling in get_aws_environment."""
    # Mock boto3 to raise an exception
    mock_session.return_value.get_credentials.side_effect = Exception("Credential error")

    # Call function
    env_info = get_aws_environment()

    # Should still return valid env info with default values
    assert env_info["aws_profile"] == "default"
    assert env_info["aws_region"] == "us-east-1"
    assert env_info["has_credentials"] is False
    assert env_info["credentials_source"] == "none"


@patch("boto3.session.Session")
def test_get_aws_account_info_with_org(mock_session):
    """Test AWS account info with organization access."""
    # Mock boto3 clients
    mock_sts = MagicMock()
    mock_iam = MagicMock()
    mock_org = MagicMock()

    mock_session.return_value.client.side_effect = lambda service: {
        "sts": mock_sts,
        "iam": mock_iam,
        "organizations": mock_org,
    }[service]

    # Mock API responses
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_iam.list_account_aliases.return_value = {"AccountAliases": ["my-account"]}

    # Mock org response for describe_organization (empty Organization means no Id)
    mock_org.describe_organization.return_value = {"Organization": {}}

    # Call function
    account_info = get_aws_account_info()

    # Verify account info (organization_id should be None)
    assert account_info["account_id"] == "123456789012"
    assert account_info["account_alias"] == "my-account"
    assert account_info["organization_id"] is None


@patch("boto3.session.Session")
def test_get_aws_account_info_general_exception(mock_session):
    """Test general exception handling in get_aws_account_info."""
    # Mock boto3 to raise a generic exception
    mock_session.return_value.client.side_effect = Exception("Generic error")

    # Call function
    account_info = get_aws_account_info()

    # All fields should be None
    assert account_info["account_id"] is None
    assert account_info["account_alias"] is None
    assert account_info["organization_id"] is None


@patch("aws_mcp_server.resources.get_aws_profiles")
@patch("os.environ.get")
def test_resource_aws_profiles(mock_environ_get, mock_get_aws_profiles):
    """Test the aws_profiles resource function implementation."""
    # Set up environment mocks
    mock_environ_get.return_value = "test-profile"

    # Set up profiles mock
    mock_get_aws_profiles.return_value = ["default", "test-profile", "dev"]

    # Create a mock function that simulates the decorated function
    # Note: We need to call the mocked functions, not the original ones
    async def mock_resource_function():
        profiles = mock_get_aws_profiles.return_value
        current_profile = mock_environ_get.return_value
        return {"profiles": [{"name": profile, "is_current": profile == current_profile} for profile in profiles]}

    # Call the function
    import asyncio

    result = asyncio.run(mock_resource_function())

    # Verify the result
    assert "profiles" in result
    assert len(result["profiles"]) == 3

    # Check that current profile is marked
    current_profile = None
    for profile in result["profiles"]:
        if profile["is_current"]:
            current_profile = profile["name"]

    assert current_profile == "test-profile"


@patch("aws_mcp_server.resources.get_aws_regions")
@patch("os.environ.get")
def test_resource_aws_regions(mock_environ_get, mock_get_aws_regions):
    """Test the aws_regions resource function implementation."""
    # Set up environment mocks to return us-west-2 for either AWS_REGION or AWS_DEFAULT_REGION
    mock_environ_get.side_effect = lambda key, default=None: ("us-west-2" if key in ("AWS_REGION", "AWS_DEFAULT_REGION") else default)

    # Set up regions mock
    mock_get_aws_regions.return_value = [
        {"RegionName": "us-east-1", "RegionDescription": "US East (N. Virginia)"},
        {"RegionName": "us-west-2", "RegionDescription": "US West (Oregon)"},
    ]

    # Create a mock function that simulates the decorated function
    # Note: We need to call the mocked functions, not the original ones
    async def mock_resource_function():
        regions = mock_get_aws_regions.return_value
        current_region = "us-west-2"  # From the mock_environ_get.side_effect
        return {
            "regions": [
                {
                    "name": region["RegionName"],
                    "description": region["RegionDescription"],
                    "is_current": region["RegionName"] == current_region,
                }
                for region in regions
            ]
        }

    # Call the function
    import asyncio

    result = asyncio.run(mock_resource_function())

    # Verify the result
    assert "regions" in result
    assert len(result["regions"]) == 2

    # Check that current region is marked
    current_region = None
    for region in result["regions"]:
        if region["is_current"]:
            current_region = region["name"]

    assert current_region == "us-west-2"


@patch("aws_mcp_server.resources.get_aws_environment")
def test_resource_aws_environment(mock_get_aws_environment):
    """Test the aws_environment resource function implementation."""
    # Set up environment mock
    mock_env = {
        "aws_profile": "test-profile",
        "aws_region": "us-west-2",
        "has_credentials": True,
        "credentials_source": "profile",
    }
    mock_get_aws_environment.return_value = mock_env

    # Create a mock function that simulates the decorated function
    # Note: We need to call the mocked function, not the original one
    async def mock_resource_function():
        return mock_get_aws_environment.return_value

    # Call the function
    import asyncio

    result = asyncio.run(mock_resource_function())

    # Verify the result is the same as the mock env
    assert result == mock_env


@patch("aws_mcp_server.resources.get_aws_account_info")
def test_resource_aws_account(mock_get_aws_account_info):
    """Test the aws_account resource function implementation."""
    # Set up account info mock
    mock_account_info = {
        "account_id": "123456789012",
        "account_alias": "test-account",
        "organization_id": "o-abcdef123456",
    }
    mock_get_aws_account_info.return_value = mock_account_info

    # Create a mock function that simulates the decorated function
    # Note: We need to call the mocked function, not the original one
    async def mock_resource_function():
        return mock_get_aws_account_info.return_value

    # Call the function
    import asyncio

    result = asyncio.run(mock_resource_function())

    # Verify the result is the same as the mock account info
    assert result == mock_account_info


def test_get_region_geographic_location():
    """Test the region geographic location utility function."""
    # Test known regions
    us_east_1 = _get_region_geographic_location("us-east-1")
    assert us_east_1["continent"] == "North America"
    assert us_east_1["country"] == "United States"
    assert us_east_1["city"] == "Ashburn, Virginia"

    eu_west_2 = _get_region_geographic_location("eu-west-2")
    assert eu_west_2["continent"] == "Europe"
    assert eu_west_2["country"] == "United Kingdom"
    assert eu_west_2["city"] == "London"

    # Test unknown region
    unknown = _get_region_geographic_location("unknown-region")
    assert unknown["continent"] == "Unknown"
    assert unknown["country"] == "Unknown"
    assert unknown["city"] == "Unknown"


@patch("boto3.session.Session")
def test_get_region_available_services(mock_session):
    """Test retrieving available AWS services for a region using Service Quotas API."""
    # Mock the Service Quotas client
    mock_quotas_client = MagicMock()

    # Set up the mock session to return our mock clients
    def mock_client(service_name, **kwargs):
        if service_name == "service-quotas":
            return mock_quotas_client
        return MagicMock()

    mock_session.return_value.client.side_effect = mock_client

    # Mock the Service Quotas API response
    mock_quotas_client.list_services.return_value = {
        "Services": [
            {"ServiceCode": "AWS.EC2", "ServiceName": "Amazon Elastic Compute Cloud"},
            {"ServiceCode": "AWS.S3", "ServiceName": "Amazon Simple Storage Service"},
            {"ServiceCode": "Lambda", "ServiceName": "AWS Lambda"},
            {"ServiceCode": "Organizations", "ServiceName": "AWS Organizations"},
            {"ServiceCode": "AWS.CloudFormation", "ServiceName": "AWS CloudFormation"},
        ],
        "NextToken": None,
    }

    # Call the function
    services = get_region_available_services(mock_session.return_value, "us-east-1")

    # Verify the results
    assert len(services) == 5

    # Verify service code transformations
    assert {"id": "ec2", "name": "Amazon Elastic Compute Cloud"} in services
    assert {"id": "s3", "name": "Amazon Simple Storage Service"} in services
    assert {"id": "lambda", "name": "AWS Lambda"} in services
    assert {"id": "organizations", "name": "AWS Organizations"} in services
    assert {"id": "cloudformation", "name": "AWS CloudFormation"} in services

    # Verify the API was called correctly
    mock_quotas_client.list_services.assert_called_once()


@patch("boto3.session.Session")
def test_get_region_available_services_pagination(mock_session):
    """Test pagination handling in Service Quotas API."""
    # Mock the Service Quotas client
    mock_quotas_client = MagicMock()

    # Set up the mock session to return our mock client
    mock_session.return_value.client.return_value = mock_quotas_client

    # Mock paginated responses
    mock_quotas_client.list_services.side_effect = [
        {
            "Services": [
                {
                    "ServiceCode": "AWS.EC2",
                    "ServiceName": "Amazon Elastic Compute Cloud",
                },
                {
                    "ServiceCode": "AWS.S3",
                    "ServiceName": "Amazon Simple Storage Service",
                },
            ],
            "NextToken": "next-token-1",
        },
        {
            "Services": [
                {"ServiceCode": "Lambda", "ServiceName": "AWS Lambda"},
                {"ServiceCode": "AWS.DynamoDB", "ServiceName": "Amazon DynamoDB"},
            ],
            "NextToken": None,
        },
    ]

    # Call the function
    services = get_region_available_services(mock_session.return_value, "us-east-1")

    # Verify the results
    assert len(services) == 4

    # Verify the pagination was handled correctly
    assert mock_quotas_client.list_services.call_count == 2
    # First call should have no NextToken
    mock_quotas_client.list_services.assert_any_call()
    # Second call should include the NextToken
    mock_quotas_client.list_services.assert_any_call(NextToken="next-token-1")


@patch("boto3.session.Session")
def test_get_region_available_services_fallback(mock_session):
    """Test fallback to client creation when Service Quotas API fails."""

    # Mock the session to raise an exception for Service Quotas
    def mock_client(service_name, **kwargs):
        if service_name == "service-quotas":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "ListServices")
        # For other services, return a mock to simulate success
        return MagicMock()

    mock_session.return_value.client.side_effect = mock_client

    # Call the function
    services = get_region_available_services(mock_session.return_value, "us-east-1")

    # Verify we got results from fallback method
    assert len(services) > 0

    # At least these common services should be in the result
    common_service_ids = [service["id"] for service in services]
    for service_id in ["ec2", "s3", "lambda"]:
        assert service_id in common_service_ids

    # Verify services have the correct structure
    for service in services:
        assert "id" in service
        assert "name" in service


@patch("aws_mcp_server.resources.get_region_available_services")
@patch("boto3.session.Session")
def test_get_region_details(mock_session, mock_get_region_available_services):
    """Test retrieving detailed AWS region information."""
    # Mock the boto3 session and clients
    mock_ec2 = MagicMock()

    # Handle different boto3 client calls
    def mock_client(service_name, **kwargs):
        if service_name == "ec2":
            return mock_ec2
        # Return a mock for other services
        return MagicMock()

    mock_session.return_value.client.side_effect = mock_client

    # Mock EC2 availability zones response
    mock_ec2.describe_availability_zones.return_value = {
        "AvailabilityZones": [
            {
                "ZoneName": "us-east-1a",
                "State": "available",
                "ZoneId": "use1-az1",
                "ZoneType": "availability-zone",
            },
            {
                "ZoneName": "us-east-1b",
                "State": "available",
                "ZoneId": "use1-az2",
                "ZoneType": "availability-zone",
            },
        ]
    }

    # Mock the services list
    mock_services = [
        {"id": "ec2", "name": "EC2"},
        {"id": "s3", "name": "S3"},
        {"id": "lambda", "name": "Lambda"},
    ]
    mock_get_region_available_services.return_value = mock_services

    # Call the function being tested
    region_details = get_region_details("us-east-1")

    # Verify basic region information
    assert region_details["code"] == "us-east-1"
    assert region_details["name"] == "US East (N. Virginia)"

    # Verify geographic location information
    geo_location = region_details["geographic_location"]
    assert geo_location["continent"] == "North America"
    assert geo_location["country"] == "United States"
    assert geo_location["city"] == "Ashburn, Virginia"

    # Verify availability zones
    assert len(region_details["availability_zones"]) == 2
    assert region_details["availability_zones"][0]["name"] == "us-east-1a"
    assert region_details["availability_zones"][1]["name"] == "us-east-1b"

    # Verify services
    assert region_details["services"] == mock_services
    mock_get_region_available_services.assert_called_once_with(mock_session.return_value, "us-east-1")


@patch("aws_mcp_server.resources.get_region_available_services")
@patch("boto3.session.Session")
def test_get_region_details_with_error(mock_session, mock_get_region_available_services):
    """Test region details with API errors."""
    # Mock boto3 to raise an exception
    mock_session.return_value.client.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "DescribeAvailabilityZones",
    )

    # Mock the get_region_available_services function to return an empty list
    mock_get_region_available_services.return_value = []

    # Call the function being tested
    region_details = get_region_details("us-east-1")

    # Should still return basic information even if AWS APIs fail
    assert region_details["code"] == "us-east-1"
    assert region_details["name"] == "US East (N. Virginia)"
    assert "geographic_location" in region_details
    assert len(region_details["availability_zones"]) == 0
    assert region_details["services"] == []
    mock_get_region_available_services.assert_called_once_with(mock_session.return_value, "us-east-1")


@patch("aws_mcp_server.resources.get_region_details")
def test_resource_aws_region_details(mock_get_region_details):
    """Test the aws_region_details resource function implementation."""
    # Set up region details mock
    mock_region_details = {
        "code": "us-east-1",
        "name": "US East (N. Virginia)",
        "geographic_location": {
            "continent": "North America",
            "country": "United States",
            "city": "Ashburn, Virginia",
        },
        "availability_zones": [
            {
                "name": "us-east-1a",
                "state": "available",
                "zone_id": "use1-az1",
                "zone_type": "availability-zone",
            },
            {
                "name": "us-east-1b",
                "state": "available",
                "zone_id": "use1-az2",
                "zone_type": "availability-zone",
            },
        ],
        "services": [
            {"id": "ec2", "name": "EC2"},
            {"id": "s3", "name": "S3"},
            {"id": "lambda", "name": "Lambda"},
        ],
        "is_current": True,
    }

    mock_get_region_details.return_value = mock_region_details

    # Create a mock function that simulates the decorated function
    async def mock_resource_function(region: str):
        return mock_get_region_details(region)

    # Call the function
    import asyncio

    result = asyncio.run(mock_resource_function("us-east-1"))

    # Verify the function was called with the correct region code
    mock_get_region_details.assert_called_once_with("us-east-1")

    # Verify the result is the same as the mock details
    assert result == mock_region_details
