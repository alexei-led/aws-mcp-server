"""Utility for executing AWS CLI commands.

This module provides functions to execute AWS CLI commands with proper error
handling, timeouts, and output processing. Commands are executed in a sandbox
environment when available.

Security Model:
- IAM policies control AWS permissions
- Sandbox provides OS-level process isolation
- Docker provides container isolation with minimal binaries
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
from aws_mcp_server.tools import CommandResult, is_pipe_command, split_pipe_command

logger = logging.getLogger(__name__)


class CommandHelpResult(TypedDict):
    """Type definition for command help results."""

    help_text: str


class CommandExecutionError(Exception):
    """Exception raised when a command fails to execute."""


def is_auth_error(error_output: str) -> bool:
    """Detect if an error is related to authentication."""
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


def format_error_message(stderr_str: str, command: str, stdout_str: str = "") -> str:
    """Format error messages to be helpful for LLM self-correction."""
    if not stderr_str:
        if stdout_str:
            return f"Command failed. Output: {stdout_str}"
        return f"Command failed with no error output. Command: '{command}'"

    if "command not found" in stderr_str.lower():
        return f"{stderr_str}\nThe command or a tool in the pipeline is not installed. Available tools: jq, grep, head, tail, sort, wc, cut, awk, sed."

    if "invalid choice" in stderr_str.lower() or "unknown command" in stderr_str.lower():
        return f"{stderr_str}\nUse aws_cli_help to see available commands for this service."

    if "missing required" in stderr_str.lower() or "required argument" in stderr_str.lower():
        return f"{stderr_str}\nUse aws_cli_help to see required parameters for this command."

    if "InvalidParameterValue" in stderr_str or "ValidationError" in stderr_str:
        return f"{stderr_str}\nCheck parameter values and formats."

    if "ResourceNotFoundException" in stderr_str or "NoSuchBucket" in stderr_str:
        return f"{stderr_str}\nThe specified resource does not exist. Verify the resource name/ARN."

    if "ThrottlingException" in stderr_str or "Rate exceeded" in stderr_str:
        return f"{stderr_str}\nAPI rate limit exceeded. Wait and retry with smaller batch sizes."

    return stderr_str


async def check_aws_cli_installed() -> bool:
    """Check if AWS CLI is installed and accessible."""
    try:
        process = await asyncio.create_subprocess_exec(
            "aws",
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        return process.returncode == 0
    except Exception as e:
        logger.debug(f"AWS CLI check failed: {e}")
        return False


def _add_ec2_region_if_needed(command: str) -> str:
    """Add region flag to EC2 commands if not already present."""
    from aws_mcp_server.config import AWS_REGION

    cmd_parts = shlex.split(command)
    is_ec2 = len(cmd_parts) >= 2 and cmd_parts[0] == "aws" and cmd_parts[1] == "ec2"
    has_region = any(part.startswith("--region") for part in cmd_parts)

    if is_ec2 and not has_region:
        command = f"{command} --region {AWS_REGION}"
        logger.debug(f"Added region to command: {command}")

    return command


def _process_output(stdout: bytes, stderr: bytes, returncode: int, command: str) -> CommandResult:
    """Process command output and return appropriate result."""
    stdout_str = stdout.decode("utf-8", errors="replace")
    stderr_str = stderr.decode("utf-8", errors="replace")

    if len(stdout_str) > MAX_OUTPUT_SIZE:
        stdout_str = stdout_str[:MAX_OUTPUT_SIZE] + "\n... (output truncated)"

    if returncode != 0:
        logger.warning(f"Command failed (code {returncode}): {command}")
        if is_auth_error(stderr_str):
            return CommandResult(
                status="error",
                output=f"Authentication error: {stderr_str}\nPlease check your AWS credentials configuration.",
            )
        return CommandResult(
            status="error",
            output=format_error_message(stderr_str, command, stdout_str),
        )

    return CommandResult(status="success", output=stdout_str)


async def execute_aws_command(command: str, timeout: int | None = None) -> CommandResult:
    """Execute a command and return the result.

    Commands are executed in a sandbox environment when available.

    Args:
        command: The command to execute
        timeout: Optional timeout in seconds (defaults to DEFAULT_TIMEOUT)

    Returns:
        CommandResult containing output and status

    Raises:
        CommandExecutionError: If the command fails to execute
    """
    if is_pipe_command(command):
        return await execute_pipe_command(command, timeout)

    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    command = _add_ec2_region_if_needed(command)
    cmd_parts = shlex.split(command)
    if not cmd_parts:
        raise CommandExecutionError("Empty command. Expected format: 'aws <service> <command> [options]' (e.g., 'aws s3 ls', 'aws ec2 describe-instances')")

    try:
        logger.debug(f"Executing: {command} (sandbox: {sandbox_available()})")

        stdout, stderr, returncode = await execute_sandboxed_async(cmd_parts, timeout=float(timeout))

        return _process_output(stdout, stderr, returncode, command)

    except asyncio.TimeoutError as e:
        raise CommandExecutionError(
            f"Command timed out after {timeout}s. For long-running operations, increase the timeout parameter (e.g., timeout=600 for 10 minutes)."
        ) from e
    except SandboxError as e:
        raise CommandExecutionError(
            f"Sandbox execution error: {e}. "
            f"The command was blocked by the OS-level sandbox. "
            f"Check if the command requires filesystem access outside allowed paths."
        ) from e
    except asyncio.CancelledError:
        raise
    except Exception as e:
        raise CommandExecutionError(f"Failed to execute command: {e}. Verify the command syntax is correct.") from e


async def execute_pipe_command(pipe_command: str, timeout: int | None = None) -> CommandResult:
    """Execute a piped command.

    All commands are executed in a sandbox environment when available.

    Args:
        pipe_command: The piped command to execute
        timeout: Optional timeout in seconds (defaults to DEFAULT_TIMEOUT)

    Returns:
        CommandResult containing output and status

    Raises:
        CommandExecutionError: If the command fails to execute
    """
    commands = split_pipe_command(pipe_command)
    if not commands:
        raise CommandExecutionError(
            "Empty command. Expected format: 'aws <service> <command> [options]' optionally piped to Unix tools (e.g., 'aws s3 ls | grep bucket')"
        )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    commands[0] = _add_ec2_region_if_needed(commands[0])

    try:
        logger.debug(f"Executing piped: {pipe_command} (sandbox: {sandbox_available()})")

        command_parts_list = [shlex.split(cmd) for cmd in commands]
        stdout, stderr, returncode = await execute_piped_sandboxed_async(command_parts_list, timeout=float(timeout))

        return _process_output(stdout, stderr, returncode, pipe_command)

    except asyncio.TimeoutError as e:
        raise CommandExecutionError(
            f"Piped command timed out after {timeout}s. For long-running operations, increase the timeout parameter (e.g., timeout=600 for 10 minutes)."
        ) from e
    except SandboxError as e:
        raise CommandExecutionError(
            f"Sandbox execution error: {e}. "
            f"The piped command was blocked by the OS-level sandbox. "
            f"Check if any command in the pipeline requires filesystem access outside allowed paths."
        ) from e
    except Exception as e:
        raise CommandExecutionError(f"Failed to execute piped command: {e}. Verify command syntax and ensure all piped tools are available.") from e


async def get_command_help(service: str, command: str | None = None) -> CommandHelpResult:
    """Get help documentation for an AWS CLI service or command.

    Raises:
        CommandExecutionError: If the help command fails to execute.
    """
    cmd_parts = ["aws", service]
    if command:
        cmd_parts.append(command)
    cmd_parts.append("help")

    cmd_str = " ".join(cmd_parts)

    result = await execute_aws_command(cmd_str)
    help_text = result["output"] if result["status"] == "success" else f"Error: {result['output']}"
    return CommandHelpResult(help_text=help_text)
