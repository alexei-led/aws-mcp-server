"""Utility for executing AWS CLI commands.

This module provides functions to validate and execute AWS CLI commands
with proper error handling, timeouts, and output processing. Commands are
executed in a sandbox environment when available for additional security.
"""

import asyncio
import logging
import shlex
from typing import TypedDict

from aws_mcp_server.config import DEFAULT_TIMEOUT, MAX_OUTPUT_SIZE
from aws_mcp_server.sandbox import (
    SandboxError,
    execute_piped_sandboxed_async,
    execute_sandboxed_async,
    sandbox_available,
)
from aws_mcp_server.security import validate_aws_command, validate_pipe_command
from aws_mcp_server.tools import CommandResult, is_pipe_command, split_pipe_command

# Configure module logger
logger = logging.getLogger(__name__)


class CommandHelpResult(TypedDict):
    """Type definition for command help results."""

    help_text: str


class CommandValidationError(Exception):
    """Exception raised when a command fails validation.

    This exception is raised when a command doesn't meet the
    validation requirements, such as starting with 'aws'.
    """

    pass


class CommandExecutionError(Exception):
    """Exception raised when a command fails to execute.

    This exception is raised when there's an error during command
    execution, such as timeouts or subprocess failures.
    """

    pass


def is_auth_error(error_output: str) -> bool:
    """Detect if an error is related to authentication.

    Args:
        error_output: The error output from AWS CLI

    Returns:
        True if the error is related to authentication, False otherwise
    """
    auth_error_patterns = [
        "Unable to locate credentials",
        "ExpiredToken",
        "AccessDenied",
        "AuthFailure",
        "The security token included in the request is invalid",
        "The config profile could not be found",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
        "Your credential profile is not properly configured",
        "credentials could not be refreshed",
        "NoCredentialProviders",
    ]
    return any(pattern in error_output for pattern in auth_error_patterns)


async def check_aws_cli_installed() -> bool:
    """Check if AWS CLI is installed and accessible.

    Returns:
        True if AWS CLI is installed, False otherwise
    """
    try:
        # Split command safely for exec
        cmd_parts = ["aws", "--version"]

        # Create subprocess using exec (safer than shell=True)
        process = await asyncio.create_subprocess_exec(
            *cmd_parts, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        return process.returncode == 0
    except Exception:
        return False


# Command validation functions are now imported from aws_mcp_server.security


async def execute_aws_command(
    command: str, timeout: int | None = None
) -> CommandResult:
    """Execute an AWS CLI command and return the result.

    Validates, executes, and processes the results of an AWS CLI command,
    handling timeouts and output size limits. Commands are executed in a
    sandbox environment when available for additional security.

    Args:
        command: The AWS CLI command to execute (must start with 'aws')
        timeout: Optional timeout in seconds (defaults to DEFAULT_TIMEOUT)

    Returns:
        CommandResult containing output and status

    Raises:
        CommandValidationError: If the command is invalid
        CommandExecutionError: If the command fails to execute
    """
    # Check if this is a piped command
    if is_pipe_command(command):
        return await execute_pipe_command(command, timeout)

    # Validate the command
    try:
        validate_aws_command(command)
    except ValueError as e:
        raise CommandValidationError(str(e)) from e

    # Set timeout
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    # Check if the command needs a region and doesn't have one specified
    from aws_mcp_server.config import AWS_REGION

    # Split by spaces and check for EC2 service specifically
    cmd_parts = shlex.split(command)
    is_ec2_command = (
        len(cmd_parts) >= 2 and cmd_parts[0] == "aws" and cmd_parts[1] == "ec2"
    )
    has_region = any(part.startswith("--region") for part in cmd_parts)

    # If it's an EC2 command and doesn't have --region
    if is_ec2_command and not has_region:
        # Add the region parameter
        command = f"{command} --region {AWS_REGION}"
        cmd_parts = shlex.split(command)
        logger.debug(f"Added region to command: {command}")

    try:
        logger.debug(
            f"Executing AWS command: {command} (sandbox: {sandbox_available()})"
        )

        # Execute in sandbox
        stdout, stderr, returncode = await execute_sandboxed_async(
            cmd_parts,
            timeout=float(timeout),
        )
        logger.debug(f"Command completed with return code: {returncode}")

        # Process output
        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")

        # Truncate output if necessary
        if len(stdout_str) > MAX_OUTPUT_SIZE:
            logger.info(
                f"Output truncated from {len(stdout_str)} to {MAX_OUTPUT_SIZE} characters"
            )
            stdout_str = stdout_str[:MAX_OUTPUT_SIZE] + "\n... (output truncated)"

        if returncode != 0:
            logger.warning(f"Command failed with return code {returncode}: {command}")
            logger.debug(f"Command error output: {stderr_str}")

            if is_auth_error(stderr_str):
                return CommandResult(
                    status="error",
                    output=f"Authentication error: {stderr_str}\nPlease check your AWS credentials.",
                )

            return CommandResult(
                status="error",
                output=stderr_str or "Command failed with no error output",
            )

        return CommandResult(status="success", output=stdout_str)

    except asyncio.TimeoutError as timeout_error:
        logger.warning(f"Command timed out after {timeout} seconds: {command}")
        raise CommandExecutionError(
            f"Command timed out after {timeout} seconds"
        ) from timeout_error
    except SandboxError as e:
        logger.error(f"Sandbox error: {e}")
        raise CommandExecutionError(f"Sandbox error: {str(e)}") from e
    except asyncio.CancelledError:
        raise
    except Exception as e:
        raise CommandExecutionError(f"Failed to execute command: {str(e)}") from e


async def execute_pipe_command(
    pipe_command: str, timeout: int | None = None
) -> CommandResult:
    """Execute a command that contains pipes.

    Validates and executes a piped command where output is fed into subsequent commands.
    The first command must be an AWS CLI command, and subsequent commands must be
    allowed Unix utilities. Commands are executed in a sandbox environment when
    available for additional security.

    Args:
        pipe_command: The piped command to execute
        timeout: Optional timeout in seconds (defaults to DEFAULT_TIMEOUT)

    Returns:
        CommandResult containing output and status

    Raises:
        CommandValidationError: If any command in the pipe is invalid
        CommandExecutionError: If the command fails to execute
    """
    # Validate the pipe command
    try:
        validate_pipe_command(pipe_command)
    except ValueError as e:
        raise CommandValidationError(f"Invalid pipe command: {str(e)}") from e
    except CommandValidationError as e:
        raise CommandValidationError(f"Invalid pipe command: {str(e)}") from e

    # Set timeout
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    # Check if the first command in the pipe is an EC2 command and needs a region
    from aws_mcp_server.config import AWS_REGION

    commands = split_pipe_command(pipe_command)
    if commands:
        # Split first command by spaces to check for EC2 service specifically
        first_cmd_parts = shlex.split(commands[0])
        is_ec2_command = (
            len(first_cmd_parts) >= 2
            and first_cmd_parts[0] == "aws"
            and first_cmd_parts[1] == "ec2"
        )
        has_region = any(part.startswith("--region") for part in first_cmd_parts)

        if is_ec2_command and not has_region:
            # Add the region parameter to the first command
            commands[0] = f"{commands[0]} --region {AWS_REGION}"
            logger.debug(f"Added region to first piped command: {commands[0]}")

    try:
        logger.debug(
            f"Executing piped command: {pipe_command} (sandbox: {sandbox_available()})"
        )

        # Convert commands to list of command parts
        command_parts_list = [shlex.split(cmd) for cmd in commands]

        # Execute the piped command in sandbox
        stdout, stderr, returncode = await execute_piped_sandboxed_async(
            command_parts_list,
            timeout=float(timeout),
        )
        logger.debug(f"Piped command completed with return code: {returncode}")

        # Process output
        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")

        # Truncate output if necessary
        if len(stdout_str) > MAX_OUTPUT_SIZE:
            logger.info(
                f"Output truncated from {len(stdout_str)} to {MAX_OUTPUT_SIZE} characters"
            )
            stdout_str = stdout_str[:MAX_OUTPUT_SIZE] + "\n... (output truncated)"

        if returncode != 0:
            logger.warning(
                f"Piped command failed with return code {returncode}: {pipe_command}"
            )
            logger.debug(f"Command error output: {stderr_str}")

            if is_auth_error(stderr_str):
                return CommandResult(
                    status="error",
                    output=f"Authentication error: {stderr_str}\nPlease check your AWS credentials.",
                )

            return CommandResult(
                status="error",
                output=stderr_str or "Command failed with no error output",
            )

        return CommandResult(status="success", output=stdout_str)

    except asyncio.TimeoutError as timeout_error:
        logger.warning(
            f"Piped command timed out after {timeout} seconds: {pipe_command}"
        )
        raise CommandExecutionError(
            f"Command timed out after {timeout} seconds"
        ) from timeout_error
    except SandboxError as e:
        logger.error(f"Sandbox error: {e}")
        raise CommandExecutionError(f"Sandbox error: {str(e)}") from e
    except Exception as e:
        raise CommandExecutionError(f"Failed to execute piped command: {str(e)}") from e


async def get_command_help(
    service: str, command: str | None = None
) -> CommandHelpResult:
    """Get help documentation for an AWS CLI service or command.

    Retrieves the help documentation for a specified AWS service or command
    by executing the appropriate AWS CLI help command.

    Args:
        service: The AWS service (e.g., s3, ec2)
        command: Optional command within the service

    Returns:
        CommandHelpResult containing the help text

    Raises:
        CommandExecutionError: If the help command fails
    """
    # Build the help command
    cmd_parts: list[str] = ["aws", service]
    if command:
        cmd_parts.append(command)
    cmd_parts.append("help")

    cmd_str = " ".join(cmd_parts)

    try:
        logger.debug(f"Getting command help for: {cmd_str}")
        result = await execute_aws_command(cmd_str)

        help_text = (
            result["output"]
            if result["status"] == "success"
            else f"Error: {result['output']}"
        )

        return CommandHelpResult(help_text=help_text)
    except CommandValidationError as e:
        logger.warning(f"Command validation error while getting help: {e}")
        return CommandHelpResult(help_text=f"Command validation error: {str(e)}")
    except CommandExecutionError as e:
        logger.warning(f"Command execution error while getting help: {e}")
        return CommandHelpResult(help_text=f"Error retrieving help: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error while getting command help: {e}", exc_info=True)
        return CommandHelpResult(help_text=f"Error retrieving help: {str(e)}")
