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

from aws_mcp_server.cli_executor import (
    CommandExecutionError,
    CommandHelpResult,
    CommandResult,
    check_aws_cli_installed,
    execute_aws_command,
    get_command_help,
)
from aws_mcp_server.config import INSTRUCTIONS
from aws_mcp_server.prompts import register_prompts
from aws_mcp_server.resources import register_resources

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("aws-mcp-server")


def run_startup_checks():
    """Run startup checks to ensure AWS CLI is installed."""
    logger.info("Running startup checks...")
    if not asyncio.run(check_aws_cli_installed()):
        logger.error("AWS CLI is not installed or not in PATH. Please install AWS CLI.")
        sys.exit(1)
    logger.info("AWS CLI is installed and available")


run_startup_checks()

mcp = FastMCP(
    "AWS MCP Server",
    instructions=INSTRUCTIONS,
)

register_prompts(mcp)
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

        result = await get_command_help(service, command)
        return result
    except Exception as e:
        logger.error(f"Error in aws_cli_help: {e}")
        return CommandHelpResult(help_text=f"Error retrieving help: {str(e)}")


@mcp.tool()
async def aws_cli_pipeline(
    command: str = Field(description="AWS CLI command, optionally piped to Unix tools for filtering and transformation"),
    timeout: int | None = Field(
        description="Optional timeout in seconds. Default: 300s. Increase for long operations.",
        default=None,
    ),
    ctx: Context | None = None,
) -> CommandResult:
    """Execute AWS CLI commands with Unix pipes for powerful data processing.

    LEVERAGE UNIX PIPES for efficient workflows:
    - jq: JSON parsing and transformation
    - grep: Pattern matching and filtering
    - head/tail: Limit output rows
    - sort/uniq: Order and deduplicate
    - wc: Count lines, words, characters
    - cut/awk: Extract specific fields
    - sed: Text substitution

    EXAMPLES:
    - aws s3 ls
    - aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId'
    - aws iam list-users | jq '.Users[].UserName'
    - aws s3api list-objects --bucket mybucket | jq '.Contents | length'
    - aws ec2 describe-instances | jq '.Reservations[].Instances[] | {id: .InstanceId, state: .State.Name}'
    - aws logs filter-log-events --log-group-name /app/logs | jq '.events[].message' | grep ERROR
    - aws cloudwatch get-metric-statistics ... | jq '.Datapoints | sort_by(.Timestamp)'

    TIPS:
    - Use --query for server-side filtering (faster, less data)
    - Use --output json for pipe-friendly output
    - Chain pipes for complex transformations

    Returns status ('success' or 'error') and command output.
    """
    logger.info(f"Executing command: {command}" + (f" with timeout: {timeout}" if timeout else ""))

    if ctx:
        is_pipe = "|" in command
        message = "Executing" + (" piped" if is_pipe else "") + " command"
        await ctx.info(message + (f" with timeout: {timeout}s" if timeout else ""))

    try:
        result = await execute_aws_command(command, timeout)

        if result["status"] == "success":
            if ctx:
                await ctx.info("Command executed successfully")
        else:
            if ctx:
                await ctx.warning("Command failed")

        return CommandResult(status=result["status"], output=result["output"])
    except CommandExecutionError as e:
        logger.warning(f"Command execution error: {e}")
        return CommandResult(status="error", output=f"Command execution error: {str(e)}")
    except Exception as e:
        logger.error(f"Error in aws_cli_pipeline: {e}")
        return CommandResult(status="error", output=f"Unexpected error: {str(e)}")
