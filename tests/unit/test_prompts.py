"""Unit tests for AWS MCP Server prompts.

Tests the prompt templates functionality in the AWS MCP Server.
"""

from unittest.mock import MagicMock

import pytest

from aws_mcp_server.prompts import register_prompts


@pytest.fixture
def prompt_functions():
    """Fixture that returns a dictionary of prompt functions.

    This fixture captures all prompt functions registered with the MCP instance.
    """
    captured_functions = {}

    # Create a special mock decorator that captures the functions
    def mock_prompt_decorator(*args, **kwargs):
        def decorator(func):
            captured_functions[func.__name__] = func
            return func

        return decorator

    mock_mcp = MagicMock()
    mock_mcp.prompt = mock_prompt_decorator

    # Register prompts with our special mock
    register_prompts(mock_mcp)

    return captured_functions


def test_prompt_registration(prompt_functions):
    """Test that prompts are registered correctly."""
    # All expected prompt names
    expected_prompt_names = [
        "create_resource",
        "security_audit",
        "cost_optimization",
        "resource_inventory",
        "troubleshoot_service",
        "iam_policy_generator",
        "service_monitoring",
        "disaster_recovery",
        "compliance_check",
        "resource_cleanup",
        "serverless_deployment",
        "container_orchestration",
        "vpc_network_design",
        "infrastructure_automation",
        "security_posture_assessment",
        "performance_tuning",
        "multi_account_governance",
    ]

    # Check that we captured the expected number of functions
    assert len(prompt_functions) == len(expected_prompt_names), f"Expected {len(expected_prompt_names)} prompts, got {len(prompt_functions)}"

    # Check that all expected prompts are registered
    for prompt_name in expected_prompt_names:
        assert prompt_name in prompt_functions, f"Expected prompt '{prompt_name}' not found"


@pytest.mark.parametrize(
    "prompt_name,args,expected_content",
    [
        (
            "create_resource",
            {"resource_type": "s3-bucket", "resource_name": "my-test-bucket"},
            ["s3-bucket", "my-test-bucket", "encryption"],
        ),
        (
            "security_audit",
            {"service": "s3"},
            ["s3", "security audit", "public access"],
        ),
        (
            "cost_optimization",
            {"service": "ec2"},
            ["ec2", "cost optimization", "unused"],
        ),
        (
            "resource_inventory",
            {"service": "ec2", "region": "us-west-2"},
            ["ec2", "--region us-west-2"],
        ),
        ("resource_inventory", {"service": "s3"}, ["s3", "resources", "--region"]),
        (
            "troubleshoot_service",
            {"service": "lambda", "resource_id": "my-function"},
            ["lambda", "my-function", "troubleshoot"],
        ),
        (
            "iam_policy_generator",
            {
                "service": "s3",
                "actions": "GetObject,PutObject",
                "resource_pattern": "arn:aws:s3:::my-bucket/*",
            },
            [
                "s3",
                "GetObject,PutObject",
                "arn:aws:s3:::my-bucket/*",
                "least-privilege",
            ],
        ),
        (
            "service_monitoring",
            {"service": "rds", "metric_type": "performance"},
            ["rds", "performance", "monitoring", "cloudwatch"],
        ),
        (
            "disaster_recovery",
            {"service": "dynamodb", "recovery_point_objective": "15 minutes"},
            ["dynamodb", "15 minutes", "disaster recovery"],
        ),
        (
            "compliance_check",
            {"compliance_standard": "HIPAA", "service": "s3"},
            ["HIPAA", "for s3", "compliance"],
        ),
        (
            "resource_cleanup",
            {"service": "ec2", "criteria": "old"},
            ["ec2", "old", "cleanup"],
        ),
        (
            "serverless_deployment",
            {"application_name": "test-app", "runtime": "python3.13"},
            ["test-app", "python3.13", "serverless", "lambda"],
        ),
        (
            "container_orchestration",
            {"cluster_name": "test-cluster", "service_type": "fargate"},
            ["test-cluster", "fargate"],
        ),
        (
            "vpc_network_design",
            {"vpc_name": "test-vpc", "cidr_block": "10.0.0.0/16"},
            ["test-vpc", "10.0.0.0/16", "VPC", "subnet"],
        ),
        (
            "infrastructure_automation",
            {"resource_type": "ec2", "automation_scope": "deployment"},
            ["ec2", "deployment", "automation"],
        ),
        ("security_posture_assessment", {}, ["securityhub", "guardduty", "assessment"]),
        (
            "performance_tuning",
            {"service": "rds", "resource_id": "test-db"},
            ["rds", "test-db", "performance"],
        ),
        (
            "multi_account_governance",
            {"account_type": "organization"},
            ["organizations", "governance"],
        ),
    ],
)
def test_prompt_templates(prompt_functions, prompt_name, args, expected_content):
    """Test all prompt templates with various inputs using parametrized tests."""
    # Get the captured function
    prompt_func = prompt_functions.get(prompt_name)
    assert prompt_func is not None, f"{prompt_name} prompt not found"

    # Test prompt output with the specified arguments
    prompt_text = prompt_func(**args)

    # Check for expected content
    for content in expected_content:
        assert content.lower() in prompt_text.lower(), f"Expected '{content}' in {prompt_name} output"
