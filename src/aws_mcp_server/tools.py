"""Command parsing utilities for AWS MCP Server.

This module provides utilities for parsing and validating commands, including:
- Unix command validation
- Pipe command detection and splitting
"""

import shlex
from typing import TypedDict

# List of allowed Unix commands that can be used in a pipe
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


def validate_unix_command(command: str) -> bool:
    """Validate that a command is an allowed Unix command.

    Args:
        command: The Unix command to validate

    Returns:
        True if the command is valid, False otherwise
    """
    cmd_parts = shlex.split(command)
    if not cmd_parts:
        return False

    # Check if the command is in the allowed list
    return cmd_parts[0] in ALLOWED_UNIX_COMMANDS


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


def split_pipe_command(pipe_command: str) -> list[str]:
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
