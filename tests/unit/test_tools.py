"""Unit tests for the tools module."""

import pytest

from aws_mcp_server.tools import is_pipe_command, split_pipe_command


@pytest.mark.parametrize(
    "command,expected",
    [
        ("aws s3 ls | grep bucket", True),
        ("aws s3api list-buckets | jq '.Buckets[].Name' | sort", True),
        ('aws s3 ls --query "Name=\\"value\\"" | grep bucket', True),
        ("aws s3 ls", False),
        ("aws ec2 describe-instances", False),
        ("aws s3 ls 's3://my-bucket/file|other'", False),
        ('aws ec2 run-instances --user-data "echo hello | grep world"', False),
        ('aws s3 ls "s3://my-bucket/file\\"|other"', False),
    ],
    ids=[
        "simple_pipe",
        "multi_pipe",
        "pipe_with_escaped_quotes",
        "no_pipe_s3",
        "no_pipe_ec2",
        "pipe_in_single_quotes",
        "pipe_in_double_quotes",
        "escaped_pipe_in_quotes",
    ],
)
def test_is_pipe_command(command, expected):
    assert is_pipe_command(command) == expected


@pytest.mark.parametrize(
    "command,expected",
    [
        ("aws s3 ls | grep bucket", ["aws s3 ls", "grep bucket"]),
        (
            "aws s3api list-buckets | jq '.Buckets[].Name' | sort",
            ["aws s3api list-buckets", "jq '.Buckets[].Name'", "sort"],
        ),
        (
            "aws s3 ls 's3://bucket/file|name' | grep 'pattern|other'",
            ["aws s3 ls 's3://bucket/file|name'", "grep 'pattern|other'"],
        ),
        (
            'aws s3 ls "s3://bucket/file|name" | grep "pattern|other"',
            ['aws s3 ls "s3://bucket/file|name"', 'grep "pattern|other"'],
        ),
        (
            'aws s3 ls --query "Name=\\"value\\"" | grep bucket',
            ['aws s3 ls --query "Name=\\"value\\""', "grep bucket"],
        ),
    ],
    ids=[
        "simple_split",
        "multi_split",
        "pipe_in_single_quoted_args",
        "pipe_in_double_quoted_args",
        "escaped_quotes_in_args",
    ],
)
def test_split_pipe_command(command, expected):
    assert split_pipe_command(command) == expected
