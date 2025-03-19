"""Main server implementation for AWS MCP Server.

This module defines the MCP server instance and tool functions for AWS CLI interaction,
providing a standardized interface for AWS CLI command execution and documentation.
"""

import asyncio
import logging
import sys

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from aws_mcp_server.cli_executor import (
    CommandExecutionError,
    CommandHelpResult,
    CommandResult,
    CommandValidationError,
    check_aws_cli_installed,
    execute_aws_command,
    get_command_help,
)
from aws_mcp_server.config import INSTRUCTIONS, SERVER_INFO

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", handlers=[logging.StreamHandler(sys.stderr)]
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
    version=SERVER_INFO["version"],
)


@mcp.tool()
async def describe_command(
    service: str = Field(description="AWS service (e.g., s3, ec2)"),
    command: str | None = Field(description="Command within the service", default=None),
    ctx: Context | None = None,
) -> CommandHelpResult:
    """Get AWS CLI command documentation.

    Retrieves the help documentation for a specified AWS service or command
    by executing the 'aws <service> [command] help' command.

    Returns:
        CommandHelpResult containing the help text
    """
    logger.info(f"Getting documentation for service: {service}, command: {command or 'None'}")

    try:
        if ctx:
            await ctx.info(f"Fetching help for AWS {service} {command or ''}")

        # Reuse the get_command_help function from cli_executor
        result = await get_command_help(service, command)
        return result
    except Exception as e:
        logger.error(f"Error in describe_command: {e}")
        return CommandHelpResult(help_text=f"Error retrieving help: {str(e)}")


@mcp.tool()
async def execute_command(
    command: str = Field(description="Complete AWS CLI command to execute"),
    timeout: int | None = Field(description="Timeout in seconds (defaults to AWS_MCP_TIMEOUT)", default=None),
    ctx: Context | None = None,
) -> CommandResult:
    """Execute an AWS CLI command.

    Validates, executes, and processes the results of an AWS CLI command,
    handling errors and formatting the output for better readability.

    Returns:
        CommandResult containing output and status
    """
    logger.info(f"Executing command: {command}" + (f" with timeout: {timeout}" if timeout else ""))

    if ctx:
        await ctx.info("Executing AWS CLI command" + (f" with timeout: {timeout}s" if timeout else ""))

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
        logger.error(f"Error in execute_command: {e}")
        return CommandResult(status="error", output=f"Unexpected error: {str(e)}")
