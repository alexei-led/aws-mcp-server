"""Command execution utilities for AWS MCP Server.

This module provides utilities for validating and executing commands, including:
- AWS CLI commands
- Basic Unix commands
- Command pipes (piping output from one command to another)
"""

import asyncio
import logging
import shlex
from typing import List, TypedDict

from aws_mcp_server.config import DEFAULT_TIMEOUT, MAX_OUTPUT_SIZE

# Configure module logger
logger = logging.getLogger(__name__)

# List of allowed Unix commands that can be used in a pipe.
#
# Security Note: These commands are whitelisted for legitimate AWS CLI output
# processing. Some commands (curl, wget, ssh, rm, etc.) could potentially be
# misused in non-Docker deployments. Docker deployment is strongly recommended
# as it provides filesystem and network isolation. The server logs a security
# warning at startup when running outside Docker.
#
# Categories:
# - Text processing (grep, sed, awk, jq): Essential for parsing AWS CLI output
# - File operations (cat, ls, head, tail): Reading and displaying data
# - Networking (curl, wget, ssh): Legitimate AWS workflows (downloading, EC2 access)
# - System info (ps, df, du): Diagnostic information
ALLOWED_UNIX_COMMANDS = [
    # File operations
    "cat",
    "ls",
    "cd",
    "pwd",
    "cp",
    "mv",
    "rm",
    "mkdir",
    "touch",
    "chmod",
    "chown",
    # Text processing
    "grep",
    "sed",
    "awk",
    "cut",
    "sort",
    "uniq",
    "wc",
    "head",
    "tail",
    "tr",
    "find",
    # System information
    "ps",
    "top",
    "df",
    "du",
    "uname",
    "whoami",
    "date",
    "which",
    "echo",
    # Networking
    "ping",
    "ifconfig",
    "netstat",
    "curl",
    "wget",
    "dig",
    "nslookup",
    "ssh",
    "scp",
    # Other utilities
    "man",
    "less",
    "tar",
    "gzip",
    "gunzip",
    "zip",
    "unzip",
    "xargs",
    "jq",
    "tee",
]


class CommandResult(TypedDict):
    """Type definition for command execution results."""

    status: str
    output: str


# Dangerous patterns in Unix commands that could be exploited for arbitrary code execution
# or other security issues. These patterns are checked against the full command string.
DANGEROUS_UNIX_PATTERNS: dict[str, list[str]] = {
    # awk can execute shell commands via system() and can pipe to shell
    "awk": [
        "system(",  # system() function executes shell commands
        "getline",  # getline can read from commands via pipe
        '|"',  # Pipe to shell
        '"\\|',  # Pipe to shell (escaped)
        '| "',  # Pipe to shell with space
    ],
    # find can execute arbitrary commands via -exec and -delete
    "find": [
        "-exec",  # Execute commands on found files
        "-execdir",  # Execute commands in file's directory
        "-ok",  # Execute with confirmation (still dangerous)
        "-okdir",  # Execute in directory with confirmation
        "-delete",  # Delete found files
    ],
    # xargs executes commands with piped arguments - inherently dangerous
    "xargs": [
        "",  # Block all xargs usage - it's designed to execute commands
    ],
    # sed can execute commands in some versions via the 'e' command
    "sed": [
        "/e",  # Execute pattern space as shell command (GNU sed)
        " e",  # Execute command flag
        ";e",  # Execute after other command
    ],
    # curl/wget data exfiltration via POST/upload
    "curl": [
        "-X POST",  # POST requests could exfiltrate data
        "--data",  # POST data
        "-d ",  # POST data shorthand
        "--upload-file",  # Upload files
        "-T ",  # Upload shorthand
        "-F ",  # Form data upload
        "--form",  # Form data upload
    ],
    "wget": [
        "--post-data",  # POST requests
        "--post-file",  # POST file contents
        "--body-data",  # Request body
        "--body-file",  # Request body from file
    ],
    # rm with dangerous flags
    "rm": [
        "-rf /",  # Recursive force delete from root
        "-rf /*",  # Recursive force delete everything
        "-rf ~",  # Recursive force delete home
        "--no-preserve-root",  # Allow deleting root
    ],
    # chmod/chown on sensitive paths
    "chmod": [
        " /",  # Modifying root or system files
        " /etc",
        " /usr",
        " /bin",
        " /sbin",
    ],
    "chown": [
        " /",  # Modifying root or system files
        " /etc",
        " /usr",
        " /bin",
        " /sbin",
    ],
}


def check_dangerous_patterns(command: str, cmd_name: str) -> str | None:
    """Check if a command contains dangerous patterns.

    Args:
        command: The full command string to check
        cmd_name: The name of the Unix command

    Returns:
        Error message if dangerous pattern found, None otherwise
    """
    if cmd_name not in DANGEROUS_UNIX_PATTERNS:
        return None

    patterns = DANGEROUS_UNIX_PATTERNS[cmd_name]
    command_lower = command.lower()

    for pattern in patterns:
        # Empty pattern means block all usage of this command
        if pattern == "":
            return f"Command '{cmd_name}' is not allowed in pipes due to security risks"

        if pattern.lower() in command_lower:
            return f"Dangerous pattern '{pattern}' detected in {cmd_name} command"

    return None


def validate_unix_command(command: str) -> bool:
    """Validate that a command is an allowed Unix command.

    This function checks both the command name against the allowlist
    and validates that no dangerous options/patterns are present.

    Args:
        command: The Unix command to validate

    Returns:
        True if the command is valid and safe, False otherwise
    """
    cmd_parts = shlex.split(command)
    if not cmd_parts:
        return False

    cmd_name = cmd_parts[0]

    # Check if the command is in the allowed list
    if cmd_name not in ALLOWED_UNIX_COMMANDS:
        return False

    # Check for dangerous patterns in specific commands
    error = check_dangerous_patterns(command, cmd_name)
    if error:
        logger.warning(f"Blocked dangerous Unix command: {error}")
        return False

    return True


def is_pipe_command(command: str) -> bool:
    """Check if a command contains a pipe operator.

    Args:
        command: The command to check

    Returns:
        True if the command contains a pipe operator, False otherwise
    """
    # Check for pipe operator that's not inside quotes
    in_single_quote = False
    in_double_quote = False
    escaped = False

    for _, char in enumerate(command):
        # Handle escape sequences
        if char == "\\" and not escaped:
            escaped = True
            continue

        if not escaped:
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
            elif char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
            elif char == "|" and not in_single_quote and not in_double_quote:
                return True

        escaped = False

    return False


def split_pipe_command(pipe_command: str) -> List[str]:
    """Split a piped command into individual commands.

    Args:
        pipe_command: The piped command string

    Returns:
        List of individual command strings
    """
    commands = []
    current_command = ""
    in_single_quote = False
    in_double_quote = False
    escaped = False

    for _, char in enumerate(pipe_command):
        # Handle escape sequences
        if char == "\\" and not escaped:
            escaped = True
            current_command += char
            continue

        if not escaped:
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                current_command += char
            elif char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                current_command += char
            elif char == "|" and not in_single_quote and not in_double_quote:
                commands.append(current_command.strip())
                current_command = ""
            else:
                current_command += char
        else:
            # Add the escaped character
            current_command += char
            escaped = False

    if current_command.strip():
        commands.append(current_command.strip())

    return commands


async def execute_piped_command(pipe_command: str, timeout: int | None = None) -> CommandResult:
    """Execute a command that contains pipes.

    Args:
        pipe_command: The piped command to execute
        timeout: Optional timeout in seconds (defaults to DEFAULT_TIMEOUT)

    Returns:
        CommandResult containing output and status
    """
    # Set timeout
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    logger.debug(f"Executing piped command: {pipe_command}")

    try:
        # Split the pipe_command into individual commands
        commands = split_pipe_command(pipe_command)

        # For each command, split it into command parts for subprocess_exec
        command_parts_list = [shlex.split(cmd) for cmd in commands]

        if len(commands) == 0:
            return CommandResult(status="error", output="Empty command")

        # Execute the first command
        first_cmd = command_parts_list[0]
        first_process = await asyncio.create_subprocess_exec(*first_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        current_process = first_process
        current_stdout = None
        current_stderr = None

        # For each additional command in the pipe, execute it with the previous command's output
        for cmd_parts in command_parts_list[1:]:
            try:
                # Wait for the previous command to complete with timeout
                current_stdout, current_stderr = await asyncio.wait_for(current_process.communicate(), timeout)

                if current_process.returncode != 0:
                    # If previous command failed, stop the pipe execution
                    stderr_str = current_stderr.decode("utf-8", errors="replace")
                    logger.warning(f"Piped command failed with return code {current_process.returncode}: {pipe_command}")
                    logger.debug(f"Command error output: {stderr_str}")
                    return CommandResult(status="error", output=stderr_str or "Command failed with no error output")

                # Create the next process with the previous output as input
                next_process = await asyncio.create_subprocess_exec(
                    *cmd_parts, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )

                # Pass the output of the previous command to the input of the next command
                stdout, stderr = await asyncio.wait_for(next_process.communicate(input=current_stdout), timeout)

                current_process = next_process
                current_stdout = stdout
                current_stderr = stderr

            except asyncio.TimeoutError:
                logger.warning(f"Piped command timed out after {timeout} seconds: {pipe_command}")
                try:
                    # process.kill() is synchronous, not a coroutine
                    current_process.kill()
                except Exception as e:
                    logger.error(f"Error killing process: {e}")
                return CommandResult(status="error", output=f"Command timed out after {timeout} seconds")

        # Wait for the final command to complete if it hasn't already
        if current_stdout is None:
            try:
                current_stdout, current_stderr = await asyncio.wait_for(current_process.communicate(), timeout)
            except asyncio.TimeoutError:
                logger.warning(f"Piped command timed out after {timeout} seconds: {pipe_command}")
                try:
                    current_process.kill()
                except Exception as e:
                    logger.error(f"Error killing process: {e}")
                return CommandResult(status="error", output=f"Command timed out after {timeout} seconds")

        # Process output
        stdout_str = current_stdout.decode("utf-8", errors="replace")
        stderr_str = current_stderr.decode("utf-8", errors="replace")

        # Truncate output if necessary
        if len(stdout_str) > MAX_OUTPUT_SIZE:
            logger.info(f"Output truncated from {len(stdout_str)} to {MAX_OUTPUT_SIZE} characters")
            stdout_str = stdout_str[:MAX_OUTPUT_SIZE] + "\n... (output truncated)"

        if current_process.returncode != 0:
            logger.warning(f"Piped command failed with return code {current_process.returncode}: {pipe_command}")
            logger.debug(f"Command error output: {stderr_str}")
            return CommandResult(status="error", output=stderr_str or "Command failed with no error output")

        return CommandResult(status="success", output=stdout_str)
    except Exception as e:
        logger.error(f"Failed to execute piped command: {str(e)}")
        return CommandResult(status="error", output=f"Failed to execute command: {str(e)}")
