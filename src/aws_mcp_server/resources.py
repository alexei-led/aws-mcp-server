"""AWS Resource definitions for the AWS MCP Server.

This module provides MCP Resources that expose AWS environment information
including available profiles, regions, and current configuration state.
"""

import configparser
import logging
import os
import re
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


def get_aws_profiles() -> list[str]:
    """Get available AWS profiles from config and credentials files.

    Reads the AWS config and credentials files to extract all available profiles.
    Supports custom credential paths via AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE
    environment variables.

    Returns:
        List of profile names
    """
    profiles = ["default"]

    config_paths = []

    custom_config = os.environ.get("AWS_CONFIG_FILE")
    if custom_config:
        config_paths.append(custom_config)
    else:
        config_paths.append(os.path.expanduser("~/.aws/config"))

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
                # Config file uses [profile xyz], credentials file uses [xyz]
                profile_match = re.match(r"profile\s+(.+)", section)
                if profile_match:
                    profile_name = profile_match.group(1)
                    if profile_name not in profiles:
                        profiles.append(profile_name)
                elif section != "default" and section not in profiles:
                    profiles.append(section)
    except (OSError, configparser.Error) as e:
        logger.warning(f"Error reading AWS profiles: {e}")

    return profiles


def get_aws_regions() -> list[dict[str, str]]:
    """Get available AWS regions.

    Uses boto3 to retrieve the list of available AWS regions.
    Automatically uses credentials from environment variables if no config file is available.

    Returns:
        List of region dictionaries with name and description
    """
    try:
        session = boto3.session.Session(region_name=os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")))
        ec2 = session.client("ec2")
        response = ec2.describe_regions()

        regions = []
        for region in response["Regions"]:
            region_name = region["RegionName"]
            description = _get_region_description(region_name)
            regions.append({"RegionName": region_name, "RegionDescription": description})

        regions.sort(key=lambda r: r["RegionName"])
        return regions
    except (BotoCoreError, ClientError) as e:
        logger.warning(f"Error fetching AWS regions: {e}")
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


def get_region_available_services(session: boto3.session.Session, region_code: str) -> list[dict[str, str]]:
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
        quotas_client = session.client("service-quotas", region_name=region_code)

        next_token = None
        while True:
            if next_token:
                response = quotas_client.list_services(NextToken=next_token)
            else:
                response = quotas_client.list_services()

            for service in response.get("Services", []):
                service_code = service.get("ServiceCode")
                if service_code:
                    # Convert ServiceQuota codes to boto3 names (remove "AWS." prefix)
                    boto3_service_id = service_code
                    if service_code.startswith("AWS."):
                        boto3_service_id = service_code[4:].lower()
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

            next_token = response.get("NextToken")
            if not next_token:
                break

    except Exception as e:
        logger.debug(f"Error fetching services with Service Quotas API for {region_code}: {e}")
        # Fall back to testing client creation for common services
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
                session.client(service_name, region_name=region_code)
                available_services.append(
                    {
                        "id": service_name,
                        "name": (service_name.upper() if service_name in ["ec2", "s3"] else service_name.replace("-", " ").title()),
                    }
                )
            except (BotoCoreError, ClientError) as e:
                logger.debug(f"Service {service_name} not available in {region_code}: {e}")

    return available_services


def _get_region_geographic_location(region_code: str) -> dict[str, str]:
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


def get_region_details(region_code: str) -> dict[str, Any]:
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
        session = boto3.session.Session(region_name=region_code)

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

        region_info["services"] = get_region_available_services(session, region_code)

    except Exception as e:
        logger.warning(f"Error fetching region details for {region_code}: {e}")

    return region_info


def get_aws_environment() -> dict[str, str]:
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
        session = boto3.session.Session()
        credentials = session.get_credentials()
        if credentials:
            env_info["has_credentials"] = True
            source = "profile"

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
    except (BotoCoreError, ClientError) as e:
        logger.warning(f"Error checking credentials: {e}")

    return env_info


def get_aws_account_info() -> dict[str, str | None]:
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
        session = boto3.session.Session(region_name=os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")))

        sts = session.client("sts")
        account_id = sts.get_caller_identity().get("Account")
        account_info["account_id"] = account_id

        if account_id:
            try:
                iam = session.client("iam")
                aliases = iam.list_account_aliases().get("AccountAliases", [])
                if aliases:
                    account_info["account_alias"] = aliases[0]
            except Exception as e:
                logger.debug(f"Error getting account alias: {e}")

            try:
                org = session.client("organizations")
                try:
                    org_response = org.describe_organization()
                    org_data = org_response.get("Organization", {})
                    if org_id := org_data.get("Id"):
                        account_info["organization_id"] = org_id
                except (BotoCoreError, ClientError) as e:
                    # Org-level call failed, try account-specific info
                    logger.debug(f"Org-level call failed, trying account-specific: {e}")
                    account_response = org.describe_account(AccountId=account_id)
                    if "Account" in account_response and "Id" in account_response["Account"]:
                        account_info["account_id"] = account_response["Account"]["Id"]
            except (BotoCoreError, ClientError) as e:
                # Organizations access is often restricted
                logger.debug(f"Error getting organization info: {e}")
    except (BotoCoreError, ClientError) as e:
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
