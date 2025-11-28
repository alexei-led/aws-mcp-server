"""Main server implementation for AWS MCP Server.

This module defines the MCP server instance and tool functions for AWS CLI interaction,
providing a standardized interface for AWS CLI command execution and documentation.
It also provides MCP Resources for AWS profiles, regions, and configuration.
"""

import asyncio
import logging
import sys

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from aws_mcp_server import __version__
from aws_mcp_server.cli_executor import (
    CommandExecutionError,
    CommandHelpResult,
    CommandResult,
    CommandValidationError,
    check_aws_cli_installed,
    execute_aws_command,
    get_command_help,
)
from aws_mcp_server.config import INSTRUCTIONS
from aws_mcp_server.prompts import register_prompts
from aws_mcp_server.resources import register_resources

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("aws-mcp-server")


# Run startup checks in synchronous context
def run_startup_checks():
    """Run startup checks to ensure AWS CLI is installed."""
    logger.info("Running startup checks...")
    if not asyncio.run(check_aws_cli_installed()):
        logger.error("AWS CLI is not installed or not in PATH. Please install AWS CLI.")
        sys.exit(1)
    logger.info("AWS CLI is installed and available")


# Call the checks
run_startup_checks()

# Create the FastMCP server following FastMCP best practices
mcp = FastMCP(
    "AWS MCP Server",
    instructions=INSTRUCTIONS,
    version=__version__,
    capabilities={"resources": {}},  # Enable resources capability
)

# Register prompt templates
register_prompts(mcp)

# Register AWS resources
register_resources(mcp)


@mcp.tool()
async def aws_cli_help(
    service: str = Field(description="AWS service name (e.g., 's3', 'ec2', 'lambda', 'iam')"),
    command: str | None = Field(
        description="Specific command to get help for (e.g., 'cp' for s3, 'describe-instances' for ec2). Omit to get service overview.",
        default=None,
    ),
    ctx: Context | None = None,
) -> CommandHelpResult:
    """Get AWS CLI documentation for any service or command.

    Use this tool BEFORE executing commands to learn:
    - Available commands for a service (omit 'command' parameter)
    - Required and optional parameters for a specific command
    - Usage examples and output format

    This is the AWS CLI's built-in help system - comprehensive and always up-to-date.

    Examples:
    - aws_cli_help(service="s3") -> lists all s3 commands
    - aws_cli_help(service="s3", command="cp") -> shows s3 cp usage, parameters, examples
    - aws_cli_help(service="ec2", command="describe-instances") -> shows filtering options
    """
    logger.info(f"Getting documentation for service: {service}, command: {command or 'None'}")

    try:
        if ctx:
            await ctx.info(f"Fetching help for AWS {service} {command or ''}")

        # Reuse the get_command_help function from cli_executor
        result = await get_command_help(service, command)
        return result
    except Exception as e:
        logger.error(f"Error in aws_cli_help: {e}")
        return CommandHelpResult(help_text=f"Error retrieving help: {str(e)}")


@mcp.tool()
async def aws_cli_pipeline(
    command: str = Field(description="Full AWS CLI command starting with 'aws'. Can include Unix pipes (|) to filter output with jq, grep, sort, etc."),
    timeout: int | None = Field(
        description="Optional timeout in seconds. Default: 300s. Increase for long operations.",
        default=None,
    ),
    ctx: Context | None = None,
) -> CommandResult:
    """Execute any AWS CLI command with optional Unix pipe processing.

    TIPS FOR EFFECTIVE USE:
    - Use --query for server-side filtering (faster, less data transfer)
    - Use --output text|json|table to control format
    - Pipe to jq for complex JSON transformations
    - Pipe to grep/sort/head for simple filtering

    COMMON PATTERNS:
    - List resources: aws s3 ls, aws ec2 describe-instances
    - Filter with --query: aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId'
    - JSON processing: aws iam list-users | jq '.Users[].UserName'
    - Count results: aws s3api list-objects --bucket X | jq '.Contents | length'

    ALLOWED PIPE COMMANDS:
    jq, grep, sed, awk, sort, uniq, head, tail, wc, cut, tr, tee, xargs

    Returns status ('success' or 'error') and command output.
    """
    logger.info(f"Executing command: {command}" + (f" with timeout: {timeout}" if timeout else ""))

    if ctx:
        is_pipe = "|" in command
        message = "Executing" + (" piped" if is_pipe else "") + " AWS CLI command"
        await ctx.info(message + (f" with timeout: {timeout}s" if timeout else ""))

    try:
        result = await execute_aws_command(command, timeout)

        # Format the output for better readability
        if result["status"] == "success":
            if ctx:
                await ctx.info("Command executed successfully")
        else:
            if ctx:
                await ctx.warning("Command failed")

        return CommandResult(status=result["status"], output=result["output"])
    except CommandValidationError as e:
        logger.warning(f"Command validation error: {e}")
        return CommandResult(status="error", output=f"Command validation error: {str(e)}")
    except CommandExecutionError as e:
        logger.warning(f"Command execution error: {e}")
        return CommandResult(status="error", output=f"Command execution error: {str(e)}")
    except Exception as e:
        logger.error(f"Error in aws_cli_pipeline: {e}")
        return CommandResult(status="error", output=f"Unexpected error: {str(e)}")
