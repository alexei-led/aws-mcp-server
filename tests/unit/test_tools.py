"""Unit tests for the tools module."""

from aws_mcp_server.tools import is_pipe_command, split_pipe_command


def test_is_pipe_command():
    """Test the is_pipe_command function."""
    # Commands with pipes
    assert is_pipe_command("aws s3 ls | grep bucket")
    assert is_pipe_command("aws s3api list-buckets | jq '.Buckets[].Name' | sort")

    # Commands without pipes
    assert not is_pipe_command("aws s3 ls")
    assert not is_pipe_command("aws ec2 describe-instances")

    # Pipes in quotes should not be detected as pipe commands
    assert not is_pipe_command("aws s3 ls 's3://my-bucket/file|other'")
    assert not is_pipe_command(
        'aws ec2 run-instances --user-data "echo hello | grep world"'
    )

    # Escaped quotes should not confuse the parser
    assert is_pipe_command('aws s3 ls --query "Name=\\"value\\"" | grep bucket')
    assert not is_pipe_command('aws s3 ls "s3://my-bucket/file\\"|other"')


def test_split_pipe_command():
    """Test the split_pipe_command function."""
    # Simple pipe command
    result = split_pipe_command("aws s3 ls | grep bucket")
    assert result == ["aws s3 ls", "grep bucket"]

    # Multi-pipe command
    result = split_pipe_command("aws s3api list-buckets | jq '.Buckets[].Name' | sort")
    assert result == ["aws s3api list-buckets", "jq '.Buckets[].Name'", "sort"]

    # Quoted pipe symbols should not split
    result = split_pipe_command(
        "aws s3 ls 's3://bucket/file|name' | grep 'pattern|other'"
    )
    assert result == ["aws s3 ls 's3://bucket/file|name'", "grep 'pattern|other'"]

    # Double quotes
    result = split_pipe_command(
        'aws s3 ls "s3://bucket/file|name" | grep "pattern|other"'
    )
    assert result == ['aws s3 ls "s3://bucket/file|name"', 'grep "pattern|other"']

    # Escaped quotes
    result = split_pipe_command('aws s3 ls --query "Name=\\"value\\"" | grep bucket')
    assert result == ['aws s3 ls --query "Name=\\"value\\""', "grep bucket"]
