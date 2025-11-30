"""Command parsing utilities for AWS MCP Server.

This module provides utilities for parsing commands:
- Pipe command detection and splitting
"""

from typing import TypedDict


class CommandResult(TypedDict):
    """Type definition for command execution results."""

    status: str
    output: str


def is_pipe_command(command: str) -> bool:
    """Check if a command contains a pipe operator.

    Args:
        command: The command to check

    Returns:
        True if the command contains a pipe operator, False otherwise
    """
    return len(split_pipe_command(command)) > 1


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

    for char in pipe_command:
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
            current_command += char
            escaped = False

    if current_command.strip():
        commands.append(current_command.strip())

    return commands
