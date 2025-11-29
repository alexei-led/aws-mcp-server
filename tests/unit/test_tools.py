"""Unit tests for the tools module."""

from aws_mcp_server.tools import (
    ALLOWED_UNIX_COMMANDS,
    is_pipe_command,
    split_pipe_command,
    validate_unix_command,
)


def test_allowed_unix_commands():
    """Test that ALLOWED_UNIX_COMMANDS contains expected commands."""
    # Verify that common Unix utilities are in the allowed list
    common_commands = ["grep", "xargs", "cat", "ls", "wc", "sort", "uniq", "jq"]
    for cmd in common_commands:
        assert cmd in ALLOWED_UNIX_COMMANDS


def test_validate_unix_command():
    """Test the validate_unix_command function."""
    # Test valid commands
    for cmd in ["grep pattern", "ls -la", "wc -l", "cat file.txt"]:
        assert validate_unix_command(cmd), f"Command should be valid: {cmd}"

    # Test invalid commands
    for cmd in ["invalid_cmd", "sudo ls", ""]:
        assert not validate_unix_command(cmd), f"Command should be invalid: {cmd}"


def test_is_pipe_command():
    """Test the is_pipe_command function."""
    # Test commands with pipes
    assert is_pipe_command("aws s3 ls | grep bucket")
    assert is_pipe_command("aws s3api list-buckets | jq '.Buckets[].Name' | sort")

    # Test commands without pipes
    assert not is_pipe_command("aws s3 ls")
    assert not is_pipe_command("aws ec2 describe-instances")

    # Test commands with pipes in quotes (should not be detected as pipe commands)
    assert not is_pipe_command("aws s3 ls 's3://my-bucket/file|other'")
    assert not is_pipe_command('aws ec2 run-instances --user-data "echo hello | grep world"')

    # Test commands with escaped quotes - these should not confuse the parser
    assert is_pipe_command('aws s3 ls --query "Name=\\"value\\"" | grep bucket')
    assert not is_pipe_command('aws s3 ls "s3://my-bucket/file\\"|other"')


def test_split_pipe_command():
    """Test the split_pipe_command function."""
    # Test simple pipe command
    cmd = "aws s3 ls | grep bucket"
    result = split_pipe_command(cmd)
    assert result == ["aws s3 ls", "grep bucket"]

    # Test multi-pipe command
    cmd = "aws s3api list-buckets | jq '.Buckets[].Name' | sort"
    result = split_pipe_command(cmd)
    assert result == ["aws s3api list-buckets", "jq '.Buckets[].Name'", "sort"]

    # Test with quoted pipe symbols (should not split inside quotes)
    cmd = "aws s3 ls 's3://bucket/file|name' | grep 'pattern|other'"
    result = split_pipe_command(cmd)
    assert result == ["aws s3 ls 's3://bucket/file|name'", "grep 'pattern|other'"]

    # Test with double quotes
    cmd = 'aws s3 ls "s3://bucket/file|name" | grep "pattern|other"'
    result = split_pipe_command(cmd)
    assert result == ['aws s3 ls "s3://bucket/file|name"', 'grep "pattern|other"']

    # Test with escaped quotes
    cmd = 'aws s3 ls --query "Name=\\"value\\"" | grep bucket'
    result = split_pipe_command(cmd)
    assert result == ['aws s3 ls --query "Name=\\"value\\""', "grep bucket"]

    # Test with escaped pipe symbol in quotes
    cmd = 'aws s3 ls "s3://bucket/file\\"|name" | grep pattern'
    result = split_pipe_command(cmd)
    assert result == ['aws s3 ls "s3://bucket/file\\"|name"', "grep pattern"]
