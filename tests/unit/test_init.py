"""Tests for the package initialization module."""

import sys
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

import pytest


@pytest.fixture
def fresh_module():
    """Remove aws_mcp_server from sys.modules for clean import."""
    if "aws_mcp_server" in sys.modules:
        del sys.modules["aws_mcp_server"]
    yield
    if "aws_mcp_server" in sys.modules:
        del sys.modules["aws_mcp_server"]


def test_version_from_package(fresh_module):
    with patch("importlib.metadata.version", return_value="1.2.3"):
        import aws_mcp_server

        assert aws_mcp_server.__version__ == "1.2.3"


def test_version_fallback_on_package_not_found(fresh_module):
    with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
        import aws_mcp_server

        assert not hasattr(aws_mcp_server, "__version__")
