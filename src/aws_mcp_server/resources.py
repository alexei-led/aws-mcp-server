"""AWS Resource definitions for the AWS MCP Server.

This module provides MCP Resources that expose AWS environment information
including available profiles, regions, and current configuration state.
"""

import configparser
import logging
import os
import re
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


def get_aws_profiles() -> List[str]:
    """Get available AWS profiles from config and credentials files.

    Reads the AWS config and credentials files to extract all available profiles.
    Supports custom credential paths via AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE
    environment variables.

    Returns:
        List of profile names
    """
    profiles = ["default"]  # default profile always exists

    # Build config paths, respecting custom locations via environment variables
    config_paths = []

    # Config file (profiles defined as [profile xyz])
    custom_config = os.environ.get("AWS_CONFIG_FILE")
    if custom_config:
        config_paths.append(custom_config)
    else:
        config_paths.append(os.path.expanduser("~/.aws/config"))

    # Credentials file (profiles defined as [xyz])
    custom_creds = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
    if custom_creds:
        config_paths.append(custom_creds)
    else:
        config_paths.append(os.path.expanduser("~/.aws/credentials"))

    try:
        for config_path in config_paths:
            if not os.path.exists(config_path):
                continue

            config = configparser.ConfigParser()
            config.read(config_path)

            for section in config.sections():
                # In config file, profiles are named [profile xyz] except default
                # In credentials file, profiles are named [xyz]
                profile_match = re.match(r"profile\s+(.+)", section)
                if profile_match:
                    # This is from config file
                    profile_name = profile_match.group(1)
                    if profile_name not in profiles:
                        profiles.append(profile_name)
                elif section != "default" and section not in profiles:
                    # This is likely from credentials file
                    profiles.append(section)
    except Exception as e:
        logger.warning(f"Error reading AWS profiles: {e}")

    return profiles


def get_aws_regions() -> List[Dict[str, str]]:
    """Get available AWS regions.

    Uses boto3 to retrieve the list of available AWS regions.
    Automatically uses credentials from environment variables if no config file is available.

    Returns:
        List of region dictionaries with name and description
    """
    try:
        # Create a session - boto3 will automatically use credentials from
        # environment variables if no config file is available
        session = boto3.session.Session(region_name=os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")))
        ec2 = session.client("ec2")
        response = ec2.describe_regions()

        # Format the regions
        regions = []
        for region in response["Regions"]:
            region_name = region["RegionName"]
            # Create a friendly name based on the region code
            description = _get_region_description(region_name)
            regions.append({"RegionName": region_name, "RegionDescription": description})

        # Sort regions by name
        regions.sort(key=lambda r: r["RegionName"])
        return regions
    except (BotoCoreError, ClientError) as e:
        logger.warning(f"Error fetching AWS regions: {e}")
        # Fallback to a static list of common regions
        return [
            {"RegionName": "us-east-1", "RegionDescription": "US East (N. Virginia)"},
            {"RegionName": "us-east-2", "RegionDescription": "US East (Ohio)"},
            {"RegionName": "us-west-1", "RegionDescription": "US West (N. California)"},
            {"RegionName": "us-west-2", "RegionDescription": "US West (Oregon)"},
            {"RegionName": "eu-west-1", "RegionDescription": "EU West (Ireland)"},
            {"RegionName": "eu-west-2", "RegionDescription": "EU West (London)"},
            {
                "RegionName": "eu-central-1",
                "RegionDescription": "EU Central (Frankfurt)",
            },
            {
                "RegionName": "ap-northeast-1",
                "RegionDescription": "Asia Pacific (Tokyo)",
            },
            {
                "RegionName": "ap-northeast-2",
                "RegionDescription": "Asia Pacific (Seoul)",
            },
            {
                "RegionName": "ap-southeast-1",
                "RegionDescription": "Asia Pacific (Singapore)",
            },
            {
                "RegionName": "ap-southeast-2",
                "RegionDescription": "Asia Pacific (Sydney)",
            },
            {
                "RegionName": "sa-east-1",
                "RegionDescription": "South America (São Paulo)",
            },
        ]
    except Exception as e:
        logger.warning(f"Unexpected error fetching AWS regions: {e}")
        return []


def _get_region_description(region_code: str) -> str:
    """Convert region code to a human-readable description.

    Args:
        region_code: AWS region code (e.g., us-east-1)

    Returns:
        Human-readable region description
    """
    region_map = {
        "us-east-1": "US East (N. Virginia)",
        "us-east-2": "US East (Ohio)",
        "us-west-1": "US West (N. California)",
        "us-west-2": "US West (Oregon)",
        "af-south-1": "Africa (Cape Town)",
        "ap-east-1": "Asia Pacific (Hong Kong)",
        "ap-south-1": "Asia Pacific (Mumbai)",
        "ap-northeast-1": "Asia Pacific (Tokyo)",
        "ap-northeast-2": "Asia Pacific (Seoul)",
        "ap-northeast-3": "Asia Pacific (Osaka)",
        "ap-southeast-1": "Asia Pacific (Singapore)",
        "ap-southeast-2": "Asia Pacific (Sydney)",
        "ap-southeast-3": "Asia Pacific (Jakarta)",
        "ca-central-1": "Canada (Central)",
        "eu-central-1": "EU Central (Frankfurt)",
        "eu-west-1": "EU West (Ireland)",
        "eu-west-2": "EU West (London)",
        "eu-west-3": "EU West (Paris)",
        "eu-north-1": "EU North (Stockholm)",
        "eu-south-1": "EU South (Milan)",
        "me-south-1": "Middle East (Bahrain)",
        "sa-east-1": "South America (São Paulo)",
    }

    return region_map.get(region_code, f"AWS Region {region_code}")


def get_region_available_services(session: boto3.session.Session, region_code: str) -> List[Dict[str, str]]:
    """Get available AWS services for a specific region.

    Uses the Service Quotas API to get a comprehensive list of services available
    in the given region. Falls back to testing client creation for common services
    if the Service Quotas API fails.

    Args:
        session: Boto3 session to use for API calls
        region_code: AWS region code (e.g., us-east-1)

    Returns:
        List of dictionaries with service ID and name
    """
    available_services = []
    try:
        # Create a Service Quotas client
        quotas_client = session.client("service-quotas", region_name=region_code)

        # List all services available in the region
        next_token = None
        while True:
            if next_token:
                response = quotas_client.list_services(NextToken=next_token)
            else:
                response = quotas_client.list_services()

            # Extract service codes
            for service in response.get("Services", []):
                service_code = service.get("ServiceCode")
                if service_code:
                    # Convert ServiceQuota service codes to boto3 service names
                    # by removing the "AWS." prefix if present
                    boto3_service_id = service_code
                    if service_code.startswith("AWS."):
                        boto3_service_id = service_code[4:].lower()
                    # Some other service codes need additional transformation
                    elif "." in service_code:
                        boto3_service_id = service_code.split(".")[-1].lower()
                    else:
                        boto3_service_id = service_code.lower()

                    available_services.append(
                        {
                            "id": boto3_service_id,
                            "name": service.get("ServiceName", service_code),
                        }
                    )

            # Check if there are more services to fetch
            next_token = response.get("NextToken")
            if not next_token:
                break

    except Exception as e:
        logger.debug(f"Error fetching services with Service Quotas API for {region_code}: {e}")
        # Fall back to the client creation method for a subset of common services
        common_services = [
            "ec2",
            "s3",
            "lambda",
            "rds",
            "dynamodb",
            "cloudformation",
            "sqs",
            "sns",
            "iam",
            "cloudwatch",
            "kinesis",
            "apigateway",
            "ecs",
            "ecr",
            "eks",
            "route53",
            "secretsmanager",
            "ssm",
            "kms",
            "elasticbeanstalk",
            "elasticache",
            "elasticsearch",
        ]

        for service_name in common_services:
            try:
                # Try to create a client for the service in the region
                # If it succeeds, the service is available
                session.client(service_name, region_name=region_code)
                available_services.append(
                    {
                        "id": service_name,
                        "name": (service_name.upper() if service_name in ["ec2", "s3"] else service_name.replace("-", " ").title()),
                    }
                )
            except Exception:
                # If client creation fails, the service might not be available in this region
                pass

    return available_services


def _get_region_geographic_location(region_code: str) -> Dict[str, str]:
    """Get geographic location information for a region.

    Args:
        region_code: AWS region code (e.g., us-east-1)

    Returns:
        Dictionary with geographic information
    """
    # Map of region codes to geographic information
    geo_map = {
        "us-east-1": {
            "continent": "North America",
            "country": "United States",
            "city": "Ashburn, Virginia",
        },
        "us-east-2": {
            "continent": "North America",
            "country": "United States",
            "city": "Columbus, Ohio",
        },
        "us-west-1": {
            "continent": "North America",
            "country": "United States",
            "city": "San Francisco, California",
        },
        "us-west-2": {
            "continent": "North America",
            "country": "United States",
            "city": "Portland, Oregon",
        },
        "af-south-1": {
            "continent": "Africa",
            "country": "South Africa",
            "city": "Cape Town",
        },
        "ap-east-1": {"continent": "Asia", "country": "China", "city": "Hong Kong"},
        "ap-south-1": {"continent": "Asia", "country": "India", "city": "Mumbai"},
        "ap-northeast-1": {"continent": "Asia", "country": "Japan", "city": "Tokyo"},
        "ap-northeast-2": {
            "continent": "Asia",
            "country": "South Korea",
            "city": "Seoul",
        },
        "ap-northeast-3": {"continent": "Asia", "country": "Japan", "city": "Osaka"},
        "ap-southeast-1": {
            "continent": "Asia",
            "country": "Singapore",
            "city": "Singapore",
        },
        "ap-southeast-2": {
            "continent": "Oceania",
            "country": "Australia",
            "city": "Sydney",
        },
        "ap-southeast-3": {
            "continent": "Asia",
            "country": "Indonesia",
            "city": "Jakarta",
        },
        "ca-central-1": {
            "continent": "North America",
            "country": "Canada",
            "city": "Montreal",
        },
        "eu-central-1": {
            "continent": "Europe",
            "country": "Germany",
            "city": "Frankfurt",
        },
        "eu-west-1": {"continent": "Europe", "country": "Ireland", "city": "Dublin"},
        "eu-west-2": {
            "continent": "Europe",
            "country": "United Kingdom",
            "city": "London",
        },
        "eu-west-3": {"continent": "Europe", "country": "France", "city": "Paris"},
        "eu-north-1": {"continent": "Europe", "country": "Sweden", "city": "Stockholm"},
        "eu-south-1": {"continent": "Europe", "country": "Italy", "city": "Milan"},
        "me-south-1": {
            "continent": "Middle East",
            "country": "Bahrain",
            "city": "Manama",
        },
        "sa-east-1": {
            "continent": "South America",
            "country": "Brazil",
            "city": "São Paulo",
        },
    }

    # Return default information if region not found
    default_geo = {"continent": "Unknown", "country": "Unknown", "city": "Unknown"}
    return geo_map.get(region_code, default_geo)


def get_region_details(region_code: str) -> Dict[str, Any]:
    """Get detailed information about a specific AWS region.

    Args:
        region_code: AWS region code (e.g., us-east-1)

    Returns:
        Dictionary with region details
    """
    region_info = {
        "code": region_code,
        "name": _get_region_description(region_code),
        "geographic_location": _get_region_geographic_location(region_code),
        "availability_zones": [],
        "services": [],
        "is_current": region_code == os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")),
    }

    try:
        # Create a session with the specified region
        session = boto3.session.Session(region_name=region_code)

        # Get availability zones
        try:
            ec2 = session.client("ec2", region_name=region_code)
            response = ec2.describe_availability_zones(Filters=[{"Name": "region-name", "Values": [region_code]}])

            azs = []
            for az in response.get("AvailabilityZones", []):
                azs.append(
                    {
                        "name": az.get("ZoneName", ""),
                        "state": az.get("State", ""),
                        "zone_id": az.get("ZoneId", ""),
                        "zone_type": az.get("ZoneType", ""),
                    }
                )

            region_info["availability_zones"] = azs
        except Exception as e:
            logger.debug(f"Error fetching availability zones for {region_code}: {e}")

        # Get available services for the region
        region_info["services"] = get_region_available_services(session, region_code)

    except Exception as e:
        logger.warning(f"Error fetching region details for {region_code}: {e}")

    return region_info


def get_aws_environment() -> Dict[str, str]:
    """Get information about the current AWS environment.

    Collects information about the active AWS environment,
    including profile, region, and credential status.
    Works with both config files and environment variables for credentials.

    Returns:
        Dictionary with AWS environment information
    """
    env_info = {
        "aws_profile": os.environ.get("AWS_PROFILE", "default"),
        "aws_region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")),
        "has_credentials": False,
        "credentials_source": "none",
    }

    try:
        # Try to load credentials from the session (preferred method)
        session = boto3.session.Session()
        credentials = session.get_credentials()
        if credentials:
            env_info["has_credentials"] = True
            source = "profile"

            # Determine credential source if possible
            if credentials.method == "shared-credentials-file":
                source = "profile"
            elif credentials.method == "environment":
                source = "environment"
            elif credentials.method == "iam-role":
                source = "instance-profile"
            elif credentials.method == "assume-role":
                source = "assume-role"
            elif credentials.method == "container-role":
                source = "container-role"

            env_info["credentials_source"] = source
    except Exception as e:
        logger.warning(f"Error checking credentials: {e}")

    return env_info


def _mask_key(key: str) -> str:
    """Mask a sensitive key for security.

    Args:
        key: The key to mask

    Returns:
        Masked key with only the first few characters visible
    """
    if not key:
        return ""

    # Show only first few characters
    visible_len = min(3, len(key))
    return key[:visible_len] + "*" * (len(key) - visible_len)


def get_aws_account_info() -> Dict[str, Optional[str]]:
    """Get information about the current AWS account.

    Uses STS to retrieve account ID and alias information.
    Automatically uses credentials from environment variables if no config file is available.

    Returns:
        Dictionary with AWS account information
    """
    account_info = {
        "account_id": None,
        "account_alias": None,
        "organization_id": None,
    }

    try:
        # Create a session - boto3 will automatically use credentials from
        # environment variables if no config file is available
        session = boto3.session.Session(region_name=os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")))

        # Get account ID from STS
        sts = session.client("sts")
        account_id = sts.get_caller_identity().get("Account")
        account_info["account_id"] = account_id

        # Try to get account alias
        if account_id:
            try:
                iam = session.client("iam")
                aliases = iam.list_account_aliases().get("AccountAliases", [])
                if aliases:
                    account_info["account_alias"] = aliases[0]
            except Exception as e:
                logger.debug(f"Error getting account alias: {e}")

            # Try to get organization info
            try:
                org = session.client("organizations")
                # First try to get organization info
                try:
                    org_response = org.describe_organization()
                    if "OrganizationId" in org_response:
                        account_info["organization_id"] = org_response["OrganizationId"]
                except Exception:
                    # Then try to get account-specific info if org-level call fails
                    account_response = org.describe_account(AccountId=account_id)
                    if "Account" in account_response and "Id" in account_response["Account"]:
                        # The account ID itself isn't the organization ID, but we might
                        # be able to extract information from other means
                        account_info["account_id"] = account_response["Account"]["Id"]
            except Exception as e:
                # Organizations access is often restricted, so this is expected to fail in many cases
                logger.debug(f"Error getting organization info: {e}")
    except Exception as e:
        logger.warning(f"Error getting AWS account info: {e}")

    return account_info


def register_resources(mcp):
    """Register all resources with the MCP server instance.

    Args:
        mcp: The FastMCP server instance
    """
    logger.info("Registering AWS resources")

    @mcp.resource(
        name="aws_profiles",
        description="Get available AWS profiles",
        uri="aws://config/profiles",
        mime_type="application/json",
    )
    async def aws_profiles() -> dict:
        """Get available AWS profiles.

        Retrieves a list of available AWS profile names from the
        AWS configuration and credentials files.

        Returns:
            Dictionary with profile information
        """
        profiles = get_aws_profiles()
        current_profile = os.environ.get("AWS_PROFILE", "default")
        return {"profiles": [{"name": profile, "is_current": profile == current_profile} for profile in profiles]}

    @mcp.resource(
        name="aws_regions",
        description="Get available AWS regions",
        uri="aws://config/regions",
        mime_type="application/json",
    )
    async def aws_regions() -> dict:
        """Get available AWS regions.

        Retrieves a list of available AWS regions with
        their descriptive names.

        Returns:
            Dictionary with region information
        """
        regions = get_aws_regions()
        current_region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
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

    @mcp.resource(
        name="aws_region_details",
        description="Get detailed information about a specific AWS region",
        uri="aws://config/regions/{region}",
        mime_type="application/json",
    )
    async def aws_region_details(region: str) -> dict:
        """Get detailed information about a specific AWS region.

        Retrieves detailed information about a specific AWS region,
        including its name, code, availability zones, geographic location,
        and available services.

        Args:
            region: AWS region code (e.g., us-east-1)

        Returns:
            Dictionary with detailed region information
        """
        logger.info(f"Getting detailed information for region: {region}")
        return get_region_details(region)

    @mcp.resource(
        name="aws_environment",
        description="Get AWS environment information",
        uri="aws://config/environment",
        mime_type="application/json",
    )
    async def aws_environment() -> dict:
        """Get AWS environment information.

        Retrieves information about the current AWS environment,
        including profile, region, and credential status.

        Returns:
            Dictionary with environment information
        """
        return get_aws_environment()

    @mcp.resource(
        name="aws_account",
        description="Get AWS account information",
        uri="aws://config/account",
        mime_type="application/json",
    )
    async def aws_account() -> dict:
        """Get AWS account information.

        Retrieves information about the current AWS account,
        including account ID and alias.

        Returns:
            Dictionary with account information
        """
        return get_aws_account_info()

    logger.info("Successfully registered all AWS resources")
